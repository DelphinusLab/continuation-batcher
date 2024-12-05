use crate::args::HashType;
use crate::args::OpenSchema;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::helpers::Serializable;
use halo2_proofs::plonk::create_witness;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::verify_proof_ext;
use halo2_proofs::plonk::verify_proof_with_shplonk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::CircuitData;
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
use std::path::PathBuf;

pub struct ProvingKeyCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, ProvingKey<E::G1Affine>>,
    pub cache_dir: PathBuf,
}

impl<E: MultiMillerLoop> ProvingKeyCache<E> {
    pub fn new(cache_size: usize, cache_dir: PathBuf) -> Self {
        let lrucache = LruCache::<String, ProvingKey<E::G1Affine>>::new(
            NonZeroUsize::new(cache_size).unwrap(),
        );
        ProvingKeyCache {
            cache: lrucache,
            cache_dir,
        }
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

    pub fn load_or_build_pkey<'a, C: Circuit<E::Scalar>>(
        &'a mut self,
        c: &C,
        params: &Params<E::G1Affine>,
        name: String,
    ) -> &'a ProvingKey<E::G1Affine> {
        load_or_build_pkey::<E, C>(
            &params,
            c,
            &self.cache_dir.join(name.clone()),
            &self.cache_dir.join(format!("{}.vkey.data", name.clone())),
            self,
        )
    }
}

pub struct ParamsCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, Params<E::G1Affine>>,
    pub cache_dir: PathBuf,
}

impl<E: MultiMillerLoop> ParamsCache<E> {
    pub fn new(cache_size: usize, cache_dir: PathBuf) -> Self {
        let lrucache =
            LruCache::<String, Params<E::G1Affine>>::new(NonZeroUsize::new(cache_size).unwrap());
        ParamsCache {
            cache: lrucache,
            cache_dir,
        }
    }
    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }
    pub fn push<'a>(&'a mut self, key: String, v: Params<E::G1Affine>) -> &'a Params<E::G1Affine> {
        self.cache.push(key.clone(), v);
        self.cache.get(&key).unwrap()
    }
    pub fn generate_k_params(&mut self, k: usize) -> &Params<E::G1Affine> {
        let params_path = &self.cache_dir.join(format!("K{}.params", k));
        load_or_build_unsafe_params::<E>(k, params_path, self)
    }
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
    pub fn new(
        name: String,
        i: usize,
        instance_size: u32,
        circuit_name_prefix: Option<String>,
    ) -> Self {
        let circuit_prefix = circuit_name_prefix.unwrap_or(name.clone());
        ProofPieceInfo {
            witness: format!("{}.{}.witness.data", name, i),
            instance: format!("{}.{}.instance.data", name, i),
            transcript: format!("{}.{}.transcript.data", name, i),
            circuit: format!("{}.circuit.data", circuit_prefix),
            instance_size,
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
    pub fn new(name: &str, k: usize, hashtype: HashType) -> Self {
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
        let fd = std::fs::File::open(configfile)
            .expect(format!("file {:?} not found", configfile).as_str());
        log::info!("read proof load info {:?}", configfile);
        serde_json::from_reader(fd).unwrap()
    }

    pub fn get_single_info(&self, name: &str, i: usize) -> Self {
        let mut info = Self::new(name, self.k, self.hashtype);
        info.append_single_proof(self.proofs[i].clone());
        info
    }
}

#[derive(Clone)]
pub struct ProofInfo<E: MultiMillerLoop> {
    pub vkey: VerifyingKey<E::G1Affine>,
    pub instances: Vec<Vec<E::Scalar>>,
    pub transcripts: Vec<u8>,
    pub k: usize,
    pub hashtype: HashType,
}

impl<E: MultiMillerLoop> ProofInfo<E> {
    pub fn load_proof(
        cache_folder: &Path,
        param_folder: &Path,
        loadinfo: &ProofGenerationInfo,
    ) -> Vec<Self> {
        let mut proofs = vec![];
        for proof_info in loadinfo.proofs.iter() {
            let vkey = read_vkey_full::<E>(&param_folder.join(proof_info.circuit.clone()));
            println!("loading instance from: {}", proof_info.instance);
            println!("loading instance size: {}", proof_info.instance_size);
            let instances = load_instance::<E>(
                &[proof_info.instance_size],
                &cache_folder.join(&proof_info.instance),
            );
            let transcripts = load_proof(&cache_folder.join(&proof_info.transcript));
            proofs.push(ProofInfo {
                vkey,
                instances,
                k: loadinfo.k,
                transcripts,
                hashtype: loadinfo.hashtype,
            });
        }
        proofs
    }

    pub fn verify_proof(
        &self,
        params_verifier: &ParamsVerifier<E>,
        open_scheme: OpenSchema,
    ) -> anyhow::Result<()> {
        let strategy = SingleVerifier::new(&params_verifier);

        match self.hashtype {
            HashType::Poseidon => verify_proof_ext(
                params_verifier,
                &self.vkey,
                strategy,
                &[&self
                    .instances
                    .iter()
                    .map(|instances| instances.as_slice())
                    .collect::<Vec<_>>()[..]],
                &mut PoseidonRead::init(&self.transcripts[..]),
                open_scheme == OpenSchema::GWC,
            )?,
            HashType::Sha => verify_proof_ext(
                params_verifier,
                &self.vkey,
                strategy,
                &[&self
                    .instances
                    .iter()
                    .map(|instances| instances.as_slice())
                    .collect::<Vec<_>>()[..]],
                &mut ShaRead::<_, _, _, sha2::Sha256>::init(&self.transcripts[..]),
                open_scheme == OpenSchema::GWC,
            )?,
            HashType::Keccak => verify_proof_ext(
                params_verifier,
                &self.vkey,
                strategy,
                &[&self
                    .instances
                    .iter()
                    .map(|instances| instances.as_slice())
                    .collect::<Vec<_>>()[..]],
                &mut ShaRead::<_, _, _, sha3::Keccak256>::init(&self.transcripts[..]),
                open_scheme == OpenSchema::GWC,
            )?,
        };

        Ok(())
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
        log::info!("K param find in cache. Key: {:?}", key);
        params_cache.cache.get(&key).as_ref().unwrap()
    } else {
        log::info!("K param not found in cache. Key: {:?}", key);
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
    fn create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
        hashtype: HashType,
        schema: OpenSchema,
    ) -> Vec<u8>;

    fn create_witness<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        param_file: String,
        k: usize,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        params_cache: &mut ParamsCache<E>,
    );
    fn mock_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        k: u32,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
    );
}

impl ProofPieceInfo {
    pub fn save_proof_data<F: FieldExt>(
        &self,
        instances: &Vec<Vec<F>>,
        transcript: &Vec<u8>,
        cache_folder: &Path,
    ) {
        // store instance in instance file
        store_instance(instances, &cache_folder.join(self.instance.as_str()));
        let cache_file = &cache_folder.join(&self.transcript);
        log::debug!("create transcripts file {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write_all(transcript).unwrap();
    }

    pub fn exec_create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        k: usize,
        pkey_cache: &mut ProvingKeyCache<E>,
        param_cache: &mut ParamsCache<E>,
        hashtype: HashType,
        schema: OpenSchema,
    ) -> Vec<u8> {
        let params = param_cache.generate_k_params(k);
        let pkey = pkey_cache.load_or_build_pkey::<C>(c, &params, self.circuit.clone());
        self.create_proof::<E, C>(c, instances, params, pkey, hashtype, schema)
    }
}

impl Prover for ProofPieceInfo {
    fn create_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
        hashtype: HashType,
        schema: OpenSchema,
    ) -> Vec<u8> {
        use ark_std::{end_timer, start_timer};

        let inputs_size = instances.iter().fold(0, |acc, x| usize::max(acc, x.len()));

        let instances: Vec<&[E::Scalar]> = instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let params_verifier: ParamsVerifier<E> = params.verifier(inputs_size).unwrap();
        let strategy = SingleVerifier::new(&params_verifier);

        #[cfg(feature = "perf")]
        let advices = {
            use halo2_proofs::plonk::generate_advice_from_synthesize;
            use std::sync::Arc;
            use zkwasm_prover::prepare_advice_buffer;

            let mut advices = Arc::new(prepare_advice_buffer(pkey, false));

            generate_advice_from_synthesize(
                &params,
                pkey,
                c,
                &instances,
                &unsafe { Arc::get_mut_unchecked(&mut advices) }
                    .iter_mut()
                    .map(|x| (&mut x[..]) as *mut [_])
                    .collect::<Vec<_>>()[..],
            );

            advices
        };

        #[cfg(feature = "perf")]
        macro_rules! perf_gen_proof {
            ($transcript: expr, $schema: expr) => {{
                use zkwasm_prover::create_proof_from_advices_with_gwc;
                use zkwasm_prover::create_proof_from_advices_with_shplonk;

                match $schema {
                    OpenSchema::GWC => create_proof_from_advices_with_gwc(
                        &params,
                        pkey,
                        &instances,
                        advices,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                    OpenSchema::Shplonk => create_proof_from_advices_with_shplonk(
                        &params,
                        pkey,
                        &instances,
                        advices,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                }
            }};
        }

        #[cfg(not(feature = "perf"))]
        macro_rules! halo2_gen_proof {
            ($transcript: expr, $schema: expr) => {
                use ark_std::rand::rngs::OsRng;
                use halo2_proofs::plonk::create_proof as create_proof_with_gwc;
                use halo2_proofs::plonk::create_proof_with_shplonk;
                match $schema {
                    OpenSchema::GWC => create_proof_with_gwc(
                        &params,
                        &pkey,
                        std::slice::from_ref(c),
                        [instances.as_slice()].as_slice(),
                        OsRng,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                    OpenSchema::Shplonk => create_proof_with_shplonk(
                        &params,
                        &pkey,
                        std::slice::from_ref(c),
                        [instances.as_slice()].as_slice(),
                        OsRng,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                }
            };
        }

        macro_rules! verify_proof {
            ($reader: expr, $schema: expr, $r: expr) => {
                match $schema {
                    OpenSchema::GWC => verify_proof(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut $reader,
                    )
                    .unwrap(),
                    OpenSchema::Shplonk => verify_proof_with_shplonk(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut $reader,
                    )
                    .unwrap(),
                }
                log::info!("verify halo2 proof succeed");
            };
        }

        let timer = start_timer!(|| "creating proof ...");
        let r = match hashtype {
            HashType::Poseidon => {
                let mut transcript = PoseidonWrite::init(vec![]);
                #[cfg(feature = "perf")]
                perf_gen_proof!(transcript, schema);
                #[cfg(not(feature = "perf"))]
                halo2_gen_proof!(transcript, schema);
                let r = transcript.finalize();
                let mut reader = PoseidonRead::init(&r[..]);
                verify_proof!(reader, schema, r);
                r
            }
            HashType::Sha => {
                let mut transcript = ShaWrite::<_, _, _, sha2::Sha256>::init(vec![]);
                #[cfg(feature = "perf")]
                perf_gen_proof!(transcript, schema);
                #[cfg(not(feature = "perf"))]
                halo2_gen_proof!(transcript, schema);
                let r = transcript.finalize();
                let mut reader = ShaRead::<_, _, _, sha2::Sha256>::init(&r[..]);
                verify_proof!(reader, schema, r);
                r
            }
            HashType::Keccak => {
                let mut transcript = ShaWrite::<_, _, _, sha3::Keccak256>::init(vec![]);
                #[cfg(feature = "perf")]
                perf_gen_proof!(transcript, schema);
                #[cfg(not(feature = "perf"))]
                halo2_gen_proof!(transcript, schema);
                let r = transcript.finalize();
                let mut reader = ShaRead::<_, _, _, sha3::Keccak256>::init(&r[..]);
                verify_proof!(reader, schema, r);
                r
            }
        };
        end_timer!(timer);
        r
    }

    fn create_witness<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        param_file: String,
        k: usize,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        param_cache: &mut ParamsCache<E>,
    ) {
        let params =
            load_or_build_unsafe_params::<E>(k, &param_folder.join(&param_file), param_cache);
        let pkey = pkey_cache.load_or_build_pkey::<C>(&c, &params, self.circuit.clone());

        let witness_file = &cache_folder.join(self.witness.clone());

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

    fn mock_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        k: u32,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
    ) {
        let prover = MockProver::run(k, c, instances.clone()).unwrap();
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
        log::info!("pkey find in cache. Key: {:?}", &key);
        pkey_cache.cache.get(&key).as_ref().unwrap()
    } else {
        log::info!("pkey not found in cache. Key: {:?}", &key);
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
            store_info_full::<E, C>(&params, vkey, circuit, cache_file);
            end_timer!(timer);
            pkey
        };
        pkey_cache.push(key, pkey)
    }
}

fn store_info_full<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    vkey: VerifyingKey<E::G1Affine>,
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
    let data = CircuitData::new(params, vkey, circuit).unwrap();
    data.write(&mut fd).unwrap();
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
    end_timer!(timer);
    let timer = start_timer!(|| "fetch pk full ...");
    let circuit_data = CircuitData::read(&mut fd).unwrap();
    let pk = circuit_data.into_proving_key(params);
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
    use std::sync::Mutex;

    const DEFAULT_CACHE_SIZE: usize = 5;

    env_logger::init();

    lazy_static::lazy_static! {
    pub static ref K_PARAMS_CACHE: Mutex<ParamsCache<Bn256>> =
        Mutex::new(ParamsCache::new(DEFAULT_CACHE_SIZE, PathBuf::from("./params")));
    }

    lazy_static::lazy_static! {
    pub static ref PKEY_CACHE: Mutex<ProvingKeyCache<Bn256>> =
        Mutex::new(ProvingKeyCache::new(DEFAULT_CACHE_SIZE, PathBuf::from("./params")));
    }

    const K: u32 = 22;

    let cache_folder = Path::new("output");
    let params_folder = Path::new("params");

    let mut proof_load_info =
        ProofGenerationInfo::new("test_circuit", K as usize, HashType::Poseidon);

    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let instances = vec![vec![Fr::from(300u64)]];
        let param_file = format!("K{}.params", K);
        let circuit_info = ProofPieceInfo::new("test_circuit".to_string(), 0, 1, None);

        // testing proof
        circuit_info.mock_proof::<Bn256, _>(K, &circuit, &instances);

        if false {
            circuit_info.create_witness(
                &circuit,
                &instances,
                param_file.clone(),
                K as usize,
                &cache_folder,
                params_folder,
                PKEY_CACHE.lock().as_mut().unwrap(),
                K_PARAMS_CACHE.lock().as_mut().unwrap(),
            );
        }

        let transcripts = circuit_info.exec_create_proof(
            &circuit,
            &instances,
            K as usize,
            PKEY_CACHE.lock().as_mut().unwrap(),
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
            HashType::Poseidon,
            OpenSchema::Shplonk,
        );

        circuit_info.save_proof_data(&instances, &transcripts, cache_folder);

        proof_load_info.append_single_proof(circuit_info);
    }

    {
        let circuit = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let instances = vec![vec![Fr::from(300u64)]];
        let circuit_info = ProofPieceInfo::new("test_circuit".to_string(), 1, 1, None);

        let transcripts = circuit_info.exec_create_proof(
            &circuit,
            &instances,
            K as usize,
            PKEY_CACHE.lock().as_mut().unwrap(),
            K_PARAMS_CACHE.lock().as_mut().unwrap(),
            HashType::Poseidon,
            OpenSchema::Shplonk,
        );

        circuit_info.save_proof_data(&instances, &transcripts, cache_folder);

        proof_load_info.append_single_proof(circuit_info);
    }

    proof_load_info.save(cache_folder);
}
