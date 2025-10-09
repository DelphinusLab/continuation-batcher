use crate::args::OpenSchema;
use crate::args::{HashType, ProveSchema};
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::arithmetic::{Engine, FieldExt};
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::create_witness;
use halo2_proofs::plonk::verify_proof_ext;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::api::VerifierKey;
use halo2aggregator_s::circuits::utils::load_instance;
use halo2aggregator_s::circuits::utils::load_proof;
use halo2aggregator_s::circuits::utils::store_instance;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::sha256::ShaRead;
use plonkish_backend::backend::hyperplonk;
use plonkish_backend::backend::hyperplonk::HyperPlonkProverParam;

use lru::LruCache;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::OpenOptions;
use std::hash::Hash;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::path::PathBuf;

use plonkish_backend::backend::PlonkishBackend;
use plonkish_backend::pcs::multilinear::Zeromorph;
use plonkish_backend::pcs::univariate::UnivariateKzg;
use plonkish_backend::IntoHalo2Error;

pub mod halo2;
pub mod hyper_plonk;

pub enum AnyProvingKey<E: MultiMillerLoop> {
    Halo2(ProvingKey<E::G1Affine>),
    HyperPlonk(HyperPlonkProverParam<E::G1Affine>),
}

impl<E: MultiMillerLoop> AnyProvingKey<E> {
    pub fn as_halo2(&self) -> Option<&ProvingKey<E::G1Affine>> {
        match self {
            AnyProvingKey::Halo2(ref pk) => Some(pk),
            _ => None,
        }
    }

    pub fn as_hyperplonk(&self) -> Option<&HyperPlonkProverParam<E::G1Affine>> {
        match self {
            AnyProvingKey::HyperPlonk(ref pk) => Some(pk),
            _ => None,
        }
    }
}

pub struct ProvingKeyCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, AnyProvingKey<E>>,
    pub cache_dir: PathBuf,
}

impl<E: MultiMillerLoop> ProvingKeyCache<E> {
    pub fn new(cache_size: usize, cache_dir: PathBuf) -> Self {
        let lrucache =
            LruCache::<String, AnyProvingKey<E>>::new(NonZeroUsize::new(cache_size).unwrap());

        ProvingKeyCache {
            cache: lrucache,
            cache_dir,
        }
    }

    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }

    pub fn get(&mut self, key: &String) -> &AnyProvingKey<E> {
        self.cache.get(key).unwrap()
    }

    pub fn push<'a>(&'a mut self, key: String, v: AnyProvingKey<E>) -> &'a AnyProvingKey<E> {
        self.cache.push(key.clone(), v);
        self.cache.get(&key).unwrap()
    }

    pub fn load_or_build_pkey<'a, C: Circuit<E::Scalar>, P: ProverBackend<E>>(
        &'a mut self,
        c: &C,
        params: &Params<E::G1Affine>,
        name: String,
    ) -> &'a P::ProverParam {
        P::load_or_build_pkey(
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
    pub prove_type: ProveSchema,
}

impl ProofPieceInfo {
    pub fn new(
        name: String,
        i: usize,
        instance_size: u32,
        circuit_name_prefix: Option<String>,
        prove_type: ProveSchema,
    ) -> Self {
        let circuit_prefix = circuit_name_prefix.unwrap_or(name.clone());
        ProofPieceInfo {
            witness: format!("{}.{}.witness.data", name, i),
            instance: format!("{}.{}.instance.data", name, i),
            transcript: format!("{}.{}.transcript.data", name, i),
            circuit: format!("{}.circuit.data", circuit_prefix),
            instance_size,
            prove_type,
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
    pub vkey: VerifierKey<E::G1Affine>,
    pub instances: Vec<Vec<E::Scalar>>,
    pub transcripts: Vec<u8>,
    pub k: usize,
    pub hashtype: HashType,
}

impl<E: MultiMillerLoop + std::fmt::Debug> ProofInfo<E>
where
    <E as Engine>::G1Affine: Serialize + DeserializeOwned,
    <E as Engine>::G2Affine: Serialize + DeserializeOwned,
    <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash,
{
    pub fn load_proof(
        cache_folder: &Path,
        param_folder: &Path,
        loadinfo: &ProofGenerationInfo,
    ) -> Vec<Self> {
        let mut proofs = vec![];
        for proof_info in loadinfo.proofs.iter() {
            let vkey = proof_info
                .prove_type
                .read_vkey::<E>(&param_folder.join(proof_info.circuit.clone()));

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

        match &self.vkey {
            VerifierKey::Halo2(vk) => match self.hashtype {
                HashType::Poseidon => verify_proof_ext(
                    params_verifier,
                    vk,
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
                    vk,
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
                    vk,
                    strategy,
                    &[&self
                        .instances
                        .iter()
                        .map(|instances| instances.as_slice())
                        .collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha3::Keccak256>::init(&self.transcripts[..]),
                    open_scheme == OpenSchema::GWC,
                )?,
            },
            VerifierKey::HyperPlonk(vk) => match self.hashtype {
                HashType::Poseidon => {
                    let kzg_vk_params =
                        plonkish_backend::pcs::univariate::UnivariateKzgVerifierParam::<E>::new(
                            params_verifier.g1,
                            params_verifier.g2,
                            params_verifier.s_g2,
                            Some(params_verifier.sum_inv_add_s_l_g2),
                        );
                    let kzg_vs = plonkish_backend::pcs::multilinear::ZeromorphKzgVerifierParam::new(
                        kzg_vk_params,
                    );
                    let vs = hyperplonk::HyperPlonkVerifierSetupParam { pcs: kzg_vs };
                    let mut reader = PoseidonRead::init(&self.transcripts[..]);
                    <hyperplonk::HyperPlonk<Zeromorph<UnivariateKzg<E>>> as PlonkishBackend<
                        E::G1Affine,
                    >>::verify(&vs, vk, &self.instances, &mut reader)
                    .into_error_halo2()?
                }
                _ => unimplemented!(),
            },
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
    fn create_proof<E: MultiMillerLoop + std::fmt::Debug, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        k: usize,
        pkey_cache: &mut ProvingKeyCache<E>,
        param_cache: &mut ParamsCache<E>,
        hashtype: HashType,
        schema: OpenSchema,
    ) -> Vec<u8>
    where
        <E as Engine>::G1Affine: Serialize + DeserializeOwned,
        <E as Engine>::G2Affine: Serialize + DeserializeOwned,
        <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash;

    fn create_witness<E: MultiMillerLoop + std::fmt::Debug, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        param_file: String,
        k: usize,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        params_cache: &mut ParamsCache<E>,
    ) where
        <E as Engine>::G1Affine: Serialize + DeserializeOwned,
        <E as Engine>::G2Affine: Serialize + DeserializeOwned,
        <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash;

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
}

impl Prover for ProofPieceInfo {
    fn create_proof<E: MultiMillerLoop + std::fmt::Debug, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        k: usize,
        pkey_cache: &mut ProvingKeyCache<E>,
        param_cache: &mut ParamsCache<E>,
        hashtype: HashType,
        schema: OpenSchema,
    ) -> Vec<u8>
    where
        <E as Engine>::G1Affine: Serialize + DeserializeOwned,
        <E as Engine>::G2Affine: Serialize + DeserializeOwned,
        <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash,
    {
        let params = param_cache.generate_k_params(k);
        match self.prove_type {
            ProveSchema::UseHalo2 => {
                let pkey = pkey_cache.load_or_build_pkey::<C, halo2::Halo2Backend<E>>(
                    c,
                    &params,
                    self.circuit.clone(),
                );
                halo2::Halo2Backend::<E>::create_proof(c, instances, params, pkey, hashtype, schema)
            }
            ProveSchema::UseHyperPlonk => {
                let pkey = pkey_cache.load_or_build_pkey::<C, hyper_plonk::HyperPlonkBackend<E>>(
                    c,
                    &params,
                    self.circuit.clone(),
                );
                hyper_plonk::HyperPlonkBackend::<E>::create_proof(
                    c, instances, params, pkey, hashtype, schema,
                )
            }
        }
    }

    fn create_witness<E: MultiMillerLoop + std::fmt::Debug, C: Circuit<E::Scalar>>(
        &self,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        param_file: String,
        k: usize,
        cache_folder: &Path,
        param_folder: &Path,
        pkey_cache: &mut ProvingKeyCache<E>,
        param_cache: &mut ParamsCache<E>,
    ) where
        <E as Engine>::G1Affine: Serialize + DeserializeOwned,
        <E as Engine>::G2Affine: Serialize + DeserializeOwned,
        <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash,
    {
        let params =
            load_or_build_unsafe_params::<E>(k, &param_folder.join(&param_file), param_cache);
        let witness_file = &cache_folder.join(self.witness.clone());
        log::info!("create witness file {:?}", witness_file);
        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(witness_file)
            .unwrap();

        match self.prove_type {
            ProveSchema::UseHalo2 => {
                let pkey = pkey_cache.load_or_build_pkey::<C, halo2::Halo2Backend<E>>(
                    &c,
                    &params,
                    self.circuit.clone(),
                );
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
            _ => unimplemented!(),
        }
    }

    fn mock_proof<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
        &self,
        k: u32,
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
    ) {
        match self.prove_type {
            ProveSchema::UseHalo2 => {
                let prover = MockProver::run(k, c, instances.clone()).unwrap();
                assert_eq!(prover.verify(), Ok(()));
            }
            _ => unimplemented!(),
        }
    }
}

pub trait ProverBackend<E: MultiMillerLoop> {
    type VerifierParam;
    type ProverParam;

    fn load_vkey<C: Circuit<E::Scalar>>(
        params: &Params<E::G1Affine>,
        param_folder: &Path,
    ) -> Self::VerifierParam;
    fn load_or_build_pkey<'a, C: Circuit<E::Scalar>>(
        params: &Params<E::G1Affine>,
        circuit: &C,
        cache_file: &Path,
        vkey_file: &Path,
        pkey_cache: &'a mut ProvingKeyCache<E>,
    ) -> &'a Self::ProverParam;
    fn store_pk_full<C: Circuit<E::Scalar>>(
        params: &Params<E::G1Affine>,
        pkey: &Self::ProverParam,
        vkey: &Self::VerifierParam,
        circuit: &C,
        cache_file: &Path,
    );
    fn read_pk_full(params: &Params<E::G1Affine>, cache_file: &Path) -> Self::ProverParam;
    fn read_vkey_full(cache_file: &Path) -> Self::VerifierParam;
    fn create_proof<C: Circuit<E::Scalar>>(
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &Self::ProverParam,
        hashtype: HashType,
        schema: OpenSchema,
    ) -> Vec<u8>;
}

impl ProveSchema {
    pub fn read_vkey<E: MultiMillerLoop + std::fmt::Debug>(
        &self,
        cache_file: &Path,
    ) -> VerifierKey<E::G1Affine>
    where
        <E as Engine>::G1Affine: Serialize + DeserializeOwned,
        <E as Engine>::G2Affine: Serialize + DeserializeOwned,
        <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash,
    {
        match self {
            ProveSchema::UseHalo2 => {
                VerifierKey::Halo2(halo2::Halo2Backend::<E>::read_vkey_full(cache_file))
            }
            ProveSchema::UseHyperPlonk => VerifierKey::HyperPlonk(
                hyper_plonk::HyperPlonkBackend::<E>::read_vkey_full(cache_file),
            ),
        }
    }
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
        let circuit_info = ProofPieceInfo::new(
            "test_circuit".to_string(),
            0,
            1,
            None,
            ProveSchema::UseHyperPlonk,
        );

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
        let circuit_info = ProofPieceInfo::new(
            "test_circuit2".to_string(),
            1,
            1,
            None,
            ProveSchema::UseHalo2,
        );

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
