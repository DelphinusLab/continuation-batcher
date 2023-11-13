use crate::args::HashType;
use ark_std::rand::rngs::OsRng;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::helpers::fetch_pk_info;
use halo2_proofs::helpers::store_pk_info;
use halo2_proofs::helpers::Serializable;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::create_proof_from_witness;
use halo2_proofs::plonk::create_witness;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuits::utils::load_instance;
use halo2aggregator_s::circuits::utils::load_or_build_vkey;
use halo2aggregator_s::circuits::utils::load_proof;
use halo2aggregator_s::circuits::utils::store_instance;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use halo2aggregator_s::transcript::sha256::ShaRead;
use halo2aggregator_s::transcript::sha256::ShaWrite;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Mutex;

const DEFAULT_CACHE_SIZE: usize = 5;

pub struct ProvingKeyCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, ProvingKey<E::G1Affine>>,
}

impl<E: MultiMillerLoop> ProvingKeyCache<E> {
    pub fn new() -> Self {
        let lrucache = LruCache::<String, ProvingKey<E::G1Affine>>::new(
            NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
        );
        ProvingKeyCache { cache: lrucache }
    }
    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }
    pub fn push<'a>(
        &'a mut self,
        key: String,
        v: ProvingKey<E::G1Affine>,
    ) -> &'a ProvingKey<E::G1Affine> {
        self.cache.push(key.clone(), v);
        self.cache.get(&key).unwrap()
    }
}

lazy_static::lazy_static! {
    pub static ref PKEY_CACHE: Mutex<ProvingKeyCache<Bn256>> =
        Mutex::new(ProvingKeyCache::new());
}

pub struct ParamsCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, Params<E::G1Affine>>,
}

impl<E: MultiMillerLoop> ParamsCache<E> {
    pub fn new() -> Self {
        let lrucache = LruCache::<String, Params<E::G1Affine>>::new(
            NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
        );
        ParamsCache { cache: lrucache }
    }
    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }
    pub fn push<'a>(
        &'a mut self,
        key: String,
        v: Params<E::G1Affine>,
    ) -> &'a Params<E::G1Affine> {
        self.cache.push(key.clone(), v);
        self.cache.get(&key).unwrap()
    }
}

lazy_static::lazy_static! {
    pub static ref K_PARAMS_CACHE: Mutex<ParamsCache<Bn256>> =
        Mutex::new(ParamsCache::new());
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofGenerationInfo {
    pub circuit: String,
    pub k: usize,
    pub instance_size: Vec<u32>,
    pub witnesses: Vec<String>,
    pub instances: Vec<String>,
    pub transcripts: Vec<String>,
    pub param: String,
    pub name: String,
    pub hashtype: HashType,
}

impl ProofGenerationInfo {
    pub fn new(
        name: &str,
        nb: usize,
        k: usize,
        instance_size: Vec<u32>,
        hashtype: HashType,
    ) -> Self {
        let mut witnesses = vec![];
        let mut instances = vec![];
        let mut transcripts = vec![];
        for i in 0..nb {
            witnesses.push(format!("{}.{}.witness.data", name, i));
            instances.push(format!("{}.{}.instance.data", name, i));
            transcripts.push(format!("{}.{}.transcripts.data", name, i));
        }
        ProofGenerationInfo {
            name: name.to_string(),
            circuit: format!("{}.circuit.data", name),
            k,
            witnesses,
            instances,
            transcripts,
            instance_size,
            param: format!("K{}.params", k),
            hashtype,
        }
    }
    pub fn save(&self, cache_folder: &Path) {
        let cache_file = cache_folder.join(format!("{}.loadinfo.json", &self.name));
        let json = serde_json::to_string_pretty(self).unwrap();
        log::info!("write proof load info {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write(json.as_bytes()).unwrap();
    }

    pub fn load(configfile: &Path) -> Self {
        let fd = std::fs::File::open(configfile).unwrap();
        log::info!("read proof load info {:?}", configfile);
        serde_json::from_reader(fd).unwrap()
    }
}

impl ProofGenerationInfo {
    pub fn create_proofs<E: MultiMillerLoop>(&self, cache_folder: &Path, param_folder: &Path, params_cache: &mut ParamsCache<E>,) {
        let params =
            load_or_build_unsafe_params::<E>(self.k, &param_folder.join(self.param.clone()), params_cache);

        let pkey = read_pk_full::<E>(&params, &param_folder.join(self.circuit.clone()));

        for ((ins, wit), trans) in self
            .instances
            .iter()
            .zip(self.witnesses.clone())
            .zip(self.transcripts.clone())
        {
            let instances = load_instance::<E>(&self.instance_size, &cache_folder.join(ins));

            let witnessfile = cache_folder.join(wit);
            let mut witnessreader = OpenOptions::new().read(true).open(witnessfile).unwrap();

            let inputs_size = self
                .instances
                .iter()
                .fold(0, |acc, x| usize::max(acc, x.len()));

            let instances: Vec<&[E::Scalar]> = instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

            let params_verifier: ParamsVerifier<E> = params.verifier(inputs_size).unwrap();
            let strategy = SingleVerifier::new(&params_verifier);

            let r = match self.hashtype {
                HashType::Poseidon => {
                    let mut transcript = PoseidonWrite::init(vec![]);
                    create_proof_from_witness(
                        &params,
                        &pkey,
                        &[instances.as_slice()],
                        OsRng,
                        &mut transcript,
                        &mut witnessreader,
                    )
                    .expect("proof generation should not fail");
                    log::info!("proof created with instance ... {:?}", self.instances);

                    let r = transcript.finalize();
                    verify_proof(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut PoseidonRead::init(&r[..]),
                    )
                    .unwrap();
                    log::info!("verify halo2 proof succeed");
                    r
                }

                HashType::Sha => {
                    let mut transcript = ShaWrite::<_, _, _, sha2::Sha256>::init(vec![]);
                    create_proof_from_witness(
                        &params,
                        &pkey,
                        &[instances.as_slice()],
                        OsRng,
                        &mut transcript,
                        &mut witnessreader,
                    )
                    .expect("proof generation should not fail");

                    let r = transcript.finalize();
                    log::info!("proof created with instance ... {:?}", self.instances);
                    verify_proof(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut ShaRead::<_, _, _, sha2::Sha256>::init(&r[..]),
                    )
                    .unwrap();
                    log::info!("verify halo2 proof succeed");
                    r
                }
            };

            let cache_file = &cache_folder.join(trans.clone());
            log::info!("create transcripts file {:?}", cache_file);
            let mut fd = std::fs::File::create(&cache_file).unwrap();
            fd.write_all(&r).unwrap();
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofLoadInfo {
    pub circuit: String,
    pub k: usize,
    pub instance_size: Vec<u32>,
    pub transcripts: Vec<String>,
    pub instances: Vec<String>,
    pub param: String,
    pub name: String,
    pub hashtype: HashType,
}

impl ProofLoadInfo {
    pub fn new(
        name: &str,
        nb: usize,
        k: usize,
        instance_size: Vec<u32>,
        hashtype: HashType,
    ) -> Self {
        let mut transcripts = vec![];
        let mut instances = vec![];
        for i in 0..nb {
            transcripts.push(format!("{}.{}.transcript.data", name, i));
            instances.push(format!("{}.{}.instance.data", name, i));
        }
        ProofLoadInfo {
            name: name.to_string(),
            circuit: format!("{}.circuit.data", name),
            k,
            transcripts,
            instances,
            instance_size,
            param: format!("K{}.params", k),
            hashtype,
        }
    }
    pub fn save(&self, cache_folder: &Path) {
        let cache_file = cache_folder.join(format!("{}.loadinfo.json", &self.name));
        log::info!("write proof load info {:?}", cache_file);
        let json = serde_json::to_string_pretty(self).unwrap();
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write(json.as_bytes()).unwrap();
    }

    pub fn load(configfile: &Path) -> Self {
        log::info!("read proof load info {:?}", configfile);
        let fd = std::fs::File::open(configfile).unwrap();
        serde_json::from_reader(fd).unwrap()
    }
}

pub struct ProofInfo<E: MultiMillerLoop> {
    pub vkey: VerifyingKey<E::G1Affine>,
    pub instances: Vec<Vec<E::Scalar>>,
    pub transcripts: Vec<u8>,
    pub k: usize,
}

impl<E: MultiMillerLoop> ProofInfo<E> {
    pub fn load_proof(
        cache_folder: &Path,
        param_folder: &Path,
        loadinfo: &ProofLoadInfo,
    ) -> Vec<Self> {
        let mut proofs = vec![];
        for (ins, trans) in loadinfo.instances.iter().zip(loadinfo.transcripts.clone()) {
            let vkey = read_vkey_full::<E>(&param_folder.join(loadinfo.circuit.clone()));
            let instances = load_instance::<E>(&loadinfo.instance_size, &cache_folder.join(ins));
            let transcripts = load_proof(&cache_folder.join(trans));
            proofs.push(ProofInfo {
                vkey,
                instances,
                k: loadinfo.k,
                transcripts,
            });
        }
        proofs
    }
}

pub fn load_or_build_unsafe_params<'a, E: MultiMillerLoop>(
    k: usize,
    cache_file: &Path,
    params_cache: &'a mut ParamsCache<E>,
) -> &'a Params<E::G1Affine> {
    use ark_std::{end_timer, start_timer};
    let key = cache_file.to_str().unwrap().to_string();
    if params_cache.contains(&key) {
        log::info!("pkey find in cache.");
        params_cache.cache.get(&key).as_ref().unwrap()
    } else {
        log::info!("K param not found in cache.");
        let params = if Path::exists(&cache_file) {
            let timer = start_timer!(|| "read K param ...");
            log::info!("read params K={} from {:?}", k, cache_file);
            let mut fd = std::fs::File::open(&cache_file).unwrap();
            let params = Params::<E::G1Affine>::read(&mut fd).unwrap();
            end_timer!(timer);
            params
        } else {
            let params = Params::<E::G1Affine>::unsafe_setup::<E>(k as u32);

            log::info!("write params K={} to {:?}", k, cache_file);
            let timer = start_timer!(|| "begin write params file ...");
            let mut fd = std::fs::File::create(&cache_file).unwrap();
            params.write(&mut fd).unwrap();
            end_timer!(timer);
            params
        };
        params_cache.push(key, params)
    }
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> CircuitInfo<E, C> {
    pub fn new(
        c: C,
        name: String,
        instances: Vec<Vec<E::Scalar>>,
        k: usize,
        hash: HashType,
    ) -> Self {
        CircuitInfo {
            circuits: vec![c],
            k,
            name: name.clone(),
            proofloadinfo: ProofLoadInfo::new(
                name.as_str(),
                1,
                k,
                instances.iter().map(|x| x.len() as u32).collect::<Vec<_>>(),
                hash,
            ),
            instances,
        }
    }
}

pub trait Prover<E: MultiMillerLoop> {
    fn create_proof(&self, params: &Params<E::G1Affine>, pkey: &ProvingKey<E::G1Affine>)
        -> Vec<u8>;
    fn create_witness(
        &self,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        index: usize,
        params_cache: &mut ParamsCache<E>,
    );
    fn mock_proof(&self, k: u32);
}

pub struct CircuitInfo<E: MultiMillerLoop, C: Circuit<E::Scalar>> {
    pub circuits: Vec<C>,
    pub name: String,
    pub k: usize,
    pub proofloadinfo: ProofLoadInfo,
    pub instances: Vec<Vec<E::Scalar>>,
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> CircuitInfo<E, C> {
    pub fn get_param<'a>(
        &'a self,
        param_folder: &Path,
        param_cache: &'a mut ParamsCache<E>,
    ) -> &'a Params<E::G1Affine> {
       load_or_build_unsafe_params::<E>(self.k, &param_folder.join(&self.proofloadinfo.param), param_cache)
    }
    pub fn get_pkey<'a>(
        &'a self,
        params: &'a Params<E::G1Affine>,
        param_folder: &Path,
        pkey_cache: &'a mut ProvingKeyCache<E>,
    ) -> &'a ProvingKey<E::G1Affine> {
        load_or_build_pkey::<E, C>(
            &params,
            self.circuits.first().unwrap(),
            &param_folder.join(self.proofloadinfo.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.name)),
            pkey_cache,
        )
    }

    pub fn exec_create_proof_with_params(
        &self,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
        cache_folder: &Path,
        index: usize,
    ) -> Vec<u8> {
        store_instance(
            &self.instances,
            &cache_folder.join(self.proofloadinfo.instances[index].as_str()),
        );

        let r = self.create_proof(params, pkey);

        let cache_file = &cache_folder.join(&self.proofloadinfo.transcripts[index]);
        log::debug!("create transcripts file {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write_all(&r).unwrap();
        r
    }

    pub fn exec_create_proof(
        &self,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        index: usize,
        param_cache: &mut ParamsCache<E>,
    ) -> Vec<u8> {
        let params =
            load_or_build_unsafe_params::<E>(self.k, &param_folder.join(&self.proofloadinfo.param), param_cache);
        let pkey = load_or_build_pkey::<E, C>(
            &params,
            self.circuits.first().unwrap(),
            &param_folder.join(self.proofloadinfo.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.name)),
            pkey_cache,
        );
        self.exec_create_proof_with_params(params, pkey, cache_folder, index)
    }
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> Prover<E> for CircuitInfo<E, C> {
    fn create_proof(
        &self,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
    ) -> Vec<u8> {
        use ark_std::{end_timer, start_timer};

        let inputs_size = self
            .instances
            .iter()
            .fold(0, |acc, x| usize::max(acc, x.len()));

        let instances: Vec<&[E::Scalar]> =
            self.instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let params_verifier: ParamsVerifier<E> = params.verifier(inputs_size).unwrap();
        let strategy = SingleVerifier::new(&params_verifier);

        let timer = start_timer!(|| "creating proof ...");
        let r = match self.proofloadinfo.hashtype {
            HashType::Poseidon => {
                let mut transcript = PoseidonWrite::init(vec![]);
                create_proof(
                    &params,
                    &pkey,
                    &self.circuits,
                    &[instances.as_slice()],
                    OsRng,
                    &mut transcript,
                )
                .expect("proof generation should not fail");

                let r = transcript.finalize();
                log::info!("proof created with instance: {:?}", self.instances);
                verify_proof(
                    &params_verifier,
                    &pkey.get_vk(),
                    strategy,
                    &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut PoseidonRead::init(&r[..]),
                )
                .unwrap();
                log::info!("verify halo2 proof succeed");
                r
            }
            HashType::Sha => {
                let mut transcript = ShaWrite::<_, _, _, sha2::Sha256>::init(vec![]);
                create_proof(
                    &params,
                    &pkey,
                    &self.circuits,
                    &[instances.as_slice()],
                    OsRng,
                    &mut transcript,
                )
                .expect("proof generation should not fail");

                let r = transcript.finalize();
                log::info!("proof created with instance ... {:?}", self.instances);
                verify_proof(
                    &params_verifier,
                    &pkey.get_vk(),
                    strategy,
                    &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha2::Sha256>::init(&r[..]),
                )
                .unwrap();
                log::info!("verify halo2 proof succeed");
                r
            }
        };
        end_timer!(timer);

        r
    }

    fn create_witness(
        &self,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        index: usize,
        param_cache: &mut ParamsCache<E>,
    ) {
        let params = load_or_build_unsafe_params::<E>(
            self.k,
            &param_folder.join(self.proofloadinfo.param.clone()),
            param_cache
        );
        let pkey = load_or_build_pkey::<E, C>(
            &params,
            self.circuits.first().unwrap(),
            &param_folder.join(self.proofloadinfo.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.name)),
            pkey_cache,
        );

        let cache_file = &cache_folder.join(format!("{}.{}.witness.data", self.name, index));

        log::info!("create witness file {:?}", cache_file);

        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&cache_file)
            .unwrap();
        create_witness(
            &params,
            pkey,
            self.circuits.first().unwrap(),
            &self
                .instances
                .iter()
                .map(|x| &x[..])
                .collect::<Vec<_>>()
                .as_slice(),
            &mut fd,
        )
        .unwrap()
    }

    fn mock_proof(&self, k: u32) {
        let prover =
            MockProver::run(k, self.circuits.first().unwrap(), self.instances.clone()).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

pub fn load_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    param_folder: &Path,
) -> VerifyingKey<E::G1Affine> {
    log::info!("read vkey from {:?}", param_folder);
    let mut fd = std::fs::File::open(&param_folder).unwrap();
    VerifyingKey::read::<_, C>(&mut fd, params).unwrap()
}

pub fn load_or_build_pkey<'a, E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    circuit: &C,
    cache_file: &Path,
    vkey_file: &Path,
    pkey_cache: &'a mut ProvingKeyCache<E>,
) -> &'a ProvingKey<E::G1Affine> {
    use ark_std::{end_timer, start_timer};
    let key = cache_file.to_str().unwrap().to_string();
    if pkey_cache.contains(&key) {
        log::info!("pkey find in cache.");
        pkey_cache.cache.get(&key).as_ref().unwrap()
    } else {
        log::info!("pkey not found in cache.");
        let pkey = if Path::exists(&cache_file) {
            let timer = start_timer!(|| "test read info full ...");
            let pkey = read_pk_full::<E>(&params, &cache_file);
            //assert_eq!(vkey.domain, pkey.get_vk().domain);
            //assert_eq!(vkey.fixed_commitments, pkey.get_vk().fixed_commitments);
            end_timer!(timer);
            pkey
        } else {
            let vkey = load_or_build_vkey::<E, C>(params, circuit, Some(vkey_file));
            let pkey =
                keygen_pk(&params, vkey.clone(), circuit).expect("keygen_pk should not fail");
            let timer = start_timer!(|| "test storing info full ...");
            store_info_full::<E, C>(&params, &vkey, circuit, cache_file);
            end_timer!(timer);
            pkey
        };
        pkey_cache.push(key, pkey)
    }
}

fn store_info_full<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    vkey: &VerifyingKey<E::G1Affine>,
    circuit: &C,
    cache_file: &Path,
) {
    log::info!("store vkey full to {:?}", cache_file);
    let mut fd = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&cache_file)
        .unwrap();
    vkey.store(&mut fd).unwrap();
    store_pk_info(params, vkey, circuit, &mut fd).unwrap();
}

pub(crate) fn read_vkey_full<E: MultiMillerLoop>(cache_file: &Path) -> VerifyingKey<E::G1Affine> {
    log::info!("read vkey full from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    VerifyingKey::<E::G1Affine>::fetch(&mut fd).unwrap()
}

pub(crate) fn read_pk_full<E: MultiMillerLoop>(
    params: &Params<E::G1Affine>,
    cache_file: &Path,
) -> ProvingKey<E::G1Affine> {
    use ark_std::{end_timer, start_timer};
    let timer = start_timer!(|| "fetch vkey full ...");
    log::info!("read vkey full from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    let vk = VerifyingKey::<E::G1Affine>::fetch(&mut fd).unwrap();
    end_timer!(timer);
    let timer = start_timer!(|| "fetch pk full ...");
    let pk = fetch_pk_info(params, &vk, &mut fd).unwrap();
    end_timer!(timer);
    pk
}

#[test]
fn batch_single_circuit() {
    //use crate::batch::BatchInfo;
    //use crate::proof::ProofInfo;
    use crate::proof::CircuitInfo;
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    env_logger::init();

    const K: u32 = 22;
    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let circuit_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit,
            "test1".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon,
        );

        circuit_info.mock_proof(K);
        let proofloadinfo = circuit_info.proofloadinfo.clone();
        circuit_info.create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        circuit_info.exec_create_proof(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );

        proofloadinfo.save(&Path::new("output"));
    }

    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let circuit_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit,
            "test2".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon,
        );

        circuit_info.mock_proof(K);
        let proofloadinfo = circuit_info.proofloadinfo.clone();
        circuit_info.create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        circuit_info.exec_create_proof(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );

        proofloadinfo.save(&Path::new("output"));
    }

    /*
    let batchinfo = BatchInfo::<Bn256> {
        proofs: ProofInfo::load_proof(&Path::new("output"), &proofloadinfo),
        target_k: K as usize,
        batch_k: BATCH_K as usize,
        commitment_check: vec![],
    };

    let agg_circuit = batchinfo.build_aggregate_circuit(&Path::new("output"), "aggregator".to_string(), HashType::Sha);
    agg_circuit.create_witness(&Path::new("output"), 0);
    agg_circuit.create_proof(&Path::new("output"), 0);
    */
}

#[test]
fn lru_drop() {
    // test should drop circuit "test2" after adding "test6".
    use crate::proof::CircuitInfo;
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    const K: u32 = 22;
    {
        let mut cproofloadinfo: Vec<ProofLoadInfo> = Vec::new();
        let mut cinfo: Vec<CircuitInfo<Bn256, SimpleCircuit<Fr>>> = Vec::new();
        for i in 1..=(DEFAULT_CACHE_SIZE + 1) {
            let circuit = || SimpleCircuit::<Fr> {
                a: Fr::from(100u64),
                b: Fr::from(200u64),
            };
            let testname = "test".to_owned() + &i.to_string();
            let circuitx_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
                circuit(),
                testname,
                vec![vec![Fr::from(300u64)]],
                K as usize,
                HashType::Poseidon,
            );
            circuitx_info.mock_proof(K);
            let proofloadinfox = circuitx_info.proofloadinfo.clone();
            cinfo.push(circuitx_info);
            cproofloadinfo.push(proofloadinfox);
        }

        for i in 0..=DEFAULT_CACHE_SIZE {
            let timer = start_timer!(|| "add circuit testx");
            cinfo.get(i).unwrap().create_witness(
                &Path::new("output"),
                &Path::new("params"),
                PKEY_CACHE.lock().as_mut().unwrap(),
                0,
                K_PARAMS_CACHE.lock().as_mut().unwrap(),
            );
            cproofloadinfo.get(i).unwrap().save(&Path::new("output"));
            end_timer!(timer);
        }

        let timer = start_timer!(|| "run circuit test1 again - should cache hit.");
        cinfo.get(0).unwrap().create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        cproofloadinfo.get(0).unwrap().save(&Path::new("output"));
        end_timer!(timer);

        let timer = start_timer!(|| "add circuit test6");
        cinfo.get(5).unwrap().create_witness(
            &Path::new("output"),
            &Path::new("params"),
            PKEY_CACHE.lock().as_mut().unwrap(),
            0,
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );
        cproofloadinfo.get(5).unwrap().save(&Path::new("output"));
        end_timer!(timer);

        let key = "params/test2.circuit.data".to_string();
        if PKEY_CACHE.lock().as_mut().unwrap().contains(&key) {
            // CACHE HIT is a bad test result.
            assert!(false)
        } else {
            // CACHE MISS is agood test.
            assert!(true)
        }
    }
}
