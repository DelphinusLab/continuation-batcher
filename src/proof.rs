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
    pub fn new(cache_size: usize) -> Self {
        let lrucache = LruCache::<String, ProvingKey<E::G1Affine>>::new(
            NonZeroUsize::new(cache_size).unwrap(),
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
        Mutex::new(ProvingKeyCache::new(DEFAULT_CACHE_SIZE));
}

pub struct ParamsCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, Params<E::G1Affine>>,
}

impl<E: MultiMillerLoop> ParamsCache<E> {
    pub fn new(cache_size: usize) -> Self {
        let lrucache = LruCache::<String, Params<E::G1Affine>>::new(
            NonZeroUsize::new(cache_size).unwrap(),
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
        Mutex::new(ParamsCache::new(DEFAULT_CACHE_SIZE));
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofPieceInfo {
    pub circuit: String,
    pub instance_size: u32,
    pub witness: String,
    pub instance: String,
    pub transcript: String,
}

impl ProofPieceInfo {
    pub fn new(name: String, i: usize, instance_size: u32) -> Self {
        ProofPieceInfo {
            witness: format!("{}.{}.witness.data", name, i),
            instance: format!("{}.{}.instance.data", name, i),
            transcript: format!("{}.{}.transcripts.data", name, i),
            circuit: format!("{}.circuit.data", name),
            instance_size
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofGenerationInfo {
    pub proofs: Vec<ProofPieceInfo>,
    pub k: usize,
    pub param: String,
    pub name: String,
    pub hashtype: HashType,
}


impl ProofGenerationInfo {
    pub fn new(
        name: &str,
        k: usize,
        hashtype: HashType,
    ) -> Self {
        ProofGenerationInfo {
            name: name.to_string(),
            k,
            proofs: vec![],
            param: format!("K{}.params", k),
            hashtype,
        }
    }
    pub fn append_single_proof(&mut self, pi: ProofPieceInfo) {
        self.proofs.push(pi)
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


        for single_proof in self.proofs.iter()
        {
            // here we only supports single instance column
            let instances = load_instance::<E>(&[single_proof.instance_size], &cache_folder.join(&single_proof.instance));

            let pkey = read_pk_full::<E>(&params, &param_folder.join(single_proof.circuit.clone()));

            let witnessfile = cache_folder.join(&single_proof.witness);
            let mut witnessreader = OpenOptions::new().read(true).open(witnessfile).unwrap();

            let inputs_size = single_proof.instance_size;
            let instances: Vec<&[E::Scalar]> = instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

            let params_verifier: ParamsVerifier<E> = params.verifier(inputs_size as usize).unwrap();
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
                    log::info!("proof created with instance ... {:?}", &single_proof.instance);

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
                    log::info!("proof created with instance ... {:?}", &single_proof.instance);
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

            let cache_file = &cache_folder.join(single_proof.instance.clone());
            log::info!("create transcripts file {:?}", cache_file);
            let mut fd = std::fs::File::create(&cache_file).unwrap();
            fd.write_all(&r).unwrap();
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofLoadInfo {
    pub k: usize,
    pub proofs: Vec<ProofPieceInfo>,
    pub param: String,
    pub name: String,
    pub hashtype: HashType,
}

impl ProofLoadInfo {
    pub fn new(
        name: &str,
        k: usize,
        hashtype: HashType,
    ) -> Self {
        ProofLoadInfo {
            name: name.to_string(),
            k,
            proofs: Vec::new(),
            param: format!("K{}.params", k),
            hashtype,
        }
    }

    pub fn append_single_proof(&mut self, pi: ProofPieceInfo) {
        self.proofs.push(pi)
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
        for proof_info in loadinfo.proofs.iter() {
            let vkey = read_vkey_full::<E>(&param_folder.join(proof_info.circuit.clone()));
            let instances = load_instance::<E>(&[proof_info.instance_size], &cache_folder.join(&proof_info.instance));
            let transcripts = load_proof(&cache_folder.join(&proof_info.transcript));
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

pub trait Prover {
    fn create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>> (
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
        hashtype: HashType,
    ) -> Vec<u8>;

    fn create_witness<E: MultiMillerLoop, C: Circuit<E::Scalar>> (
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        param_file: String,
        witness_file: String,
        k: usize,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        params_cache: &mut ParamsCache<E>,
    );
    fn mock_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>> (
        &self, k: u32,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
    );
}

impl ProofPieceInfo {
    pub fn exec_create_proof_with_params<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
        cache_folder: &Path,
        hashtype: HashType,
    ) -> Vec<u8> {
        // store instance in instance file
        store_instance(
            instances,
            &cache_folder.join(self.instance.as_str()),
        );

        let r = self.create_proof::<E, C>(c, instances, params, pkey, hashtype);

        let cache_file = &cache_folder.join(&self.transcript);
        log::debug!("create transcripts file {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write_all(&r).unwrap();
        r
    }

    pub fn exec_create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        cache_folder: &Path,
        param_folder: &Path,
        param_file: String,
        k: usize,
        pkey_cache: &mut ProvingKeyCache<E>,
        param_cache: &mut ParamsCache<E>,
        hashtype: HashType,
    ) -> Vec<u8> {
        let params = load_or_build_unsafe_params::<E>(k, &param_folder.join(&param_file), param_cache);
        let pkey = load_or_build_pkey::<E, C>(
            &params,
            c,
            &param_folder.join(self.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.circuit)),
            pkey_cache,
        );

        self.exec_create_proof_with_params::<E, C>(c, instances,params, pkey, cache_folder, hashtype)
    }
}

impl Prover for ProofPieceInfo {
    fn create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>> (
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
        hashtype: HashType,
    ) -> Vec<u8> {
        use ark_std::{end_timer, start_timer};

        let inputs_size = instances
            .iter()
            .fold(0, |acc, x| usize::max(acc, x.len()));

        let instances: Vec<&[E::Scalar]> =
            instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let params_verifier: ParamsVerifier<E> = params.verifier(inputs_size).unwrap();
        let strategy = SingleVerifier::new(&params_verifier);

        let timer = start_timer!(|| "creating proof ...");
        let r = match hashtype {
            HashType::Poseidon => {
                let mut transcript = PoseidonWrite::init(vec![]);
                create_proof(
                    &params,
                    &pkey,
                    std::slice::from_ref(c),
                    &[instances.as_slice()],
                    OsRng,
                    &mut transcript,
                )
                .expect("proof generation should not fail");

                let r = transcript.finalize();
                log::info!("proof created with instance: {:?}", instances);
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
                    std::slice::from_ref(c),
                    &[instances.as_slice()],
                    OsRng,
                    &mut transcript,
                )
                .expect("proof generation should not fail");

                let r = transcript.finalize();
                log::info!("proof created with instance ... {:?}", instances);
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

    fn create_witness<E: MultiMillerLoop, C: Circuit<E::Scalar>> (
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        param_file: String,
        witness_file: String,
        k: usize,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        param_cache: &mut ParamsCache<E>,
    ) {

        let params = load_or_build_unsafe_params::<E>(k, &param_folder.join(&param_file), param_cache);
        let pkey = load_or_build_pkey::<E, C>(
            &params,
            c,
            &param_folder.join(self.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.circuit)),
            pkey_cache,
        );

        let witness_file = &cache_folder.join(witness_file);

        log::info!("create witness file {:?}", witness_file);

        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(witness_file)
            .unwrap();

        create_witness(
            &params,
            pkey,
            c,
            instances
                .iter()
                .map(|x| &x[..])
                .collect::<Vec<_>>()
                .as_slice(),
            &mut fd,
        )
        .unwrap()
    }

    fn mock_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>> (
        &self,
        k: u32,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
    ) {

        let prover =
            MockProver::run(k, c, instances.clone()).unwrap();
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
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    env_logger::init();

    const K: u32 = 22;

    let cache_folder = Path::new("output"); 
    let params_folder = Path::new("params"); 

    let mut proof_load_info = ProofLoadInfo::new(
        "test_circuit",
        K as usize,
        HashType::Poseidon
    );


    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let instances = vec![vec![Fr::from(300u64)]];
        let param_file = format!("K{}.params", K);
        let circuit_info = ProofPieceInfo::new("test_circuit".to_string(), 0, 1);

        // testing proof
        circuit_info.mock_proof::<Bn256, _>(K, &circuit, &instances);

        // testing proof witness generation
        let witness_file = format!("{}.{}.witness.data", circuit_info.circuit, 0);

        circuit_info.create_witness(
            &circuit,
            &instances,
            param_file.clone(),
            witness_file,
            K as usize,
            &cache_folder,
            params_folder,
            PKEY_CACHE.lock().as_mut().unwrap(),
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
        );

        circuit_info.exec_create_proof(
            &circuit,
            &instances,
            &cache_folder, 
            &params_folder,
            param_file,
            K as usize,
            PKEY_CACHE.lock().as_mut().unwrap(),
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
            HashType::Poseidon
        );


        proof_load_info.append_single_proof(circuit_info);
    }

    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let instances = vec![vec![Fr::from(300u64)]];
        let param_file = format!("K{}.params", K);
        let circuit_info = ProofPieceInfo::new("test_circuit".to_string(), 1, 1);

        circuit_info.exec_create_proof(
            &circuit,
            &instances,
            &cache_folder, 
            &params_folder,
            param_file,
            K as usize,
            PKEY_CACHE.lock().as_mut().unwrap(),
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
            HashType::Poseidon
        );

        let proof_load_info = ProofLoadInfo::new(
            circuit_info.circuit.as_str(),
            K as usize,
            HashType::Poseidon
        );

        proof_load_info.append_single_proof(circuit_info);
    }
    proof_load_info.save(cache_folder);


    /*
    let batchinfo = BatchInfo::<Bn256> {
        proofs: ProofInfo::load_proof(cache_folder, params_folder, &proof_load_info),
        target_k: K as usize,
        batch_k: K as usize,
        equivalents: vec![],
        expose: vec![],
        absorb: vec![],
    };

    let agg_circuit = batchinfo.build_aggregate_circuit(&Path::new("output"), "aggregator".to_string(), HashType::Sha);
    agg_circuit.create_witness(&Path::new("output"), 0);
    agg_circuit.create_proof(&Path::new("output"), 0);
    */
}
