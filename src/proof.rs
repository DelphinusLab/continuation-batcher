use halo2_proofs::helpers::fetch_pk_info;
use halo2_proofs::helpers::store_pk_info;
use halo2_proofs::helpers::Serializable;
use ark_std::rand::rngs::OsRng;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::create_proof_from_witness;
use halo2_proofs::plonk::create_witness;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuits::utils::load_instance;
use halo2aggregator_s::circuits::utils::load_proof;
use halo2aggregator_s::circuits::utils::store_instance;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use halo2aggregator_s::transcript::sha256::ShaRead;
use halo2aggregator_s::transcript::sha256::ShaWrite;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::args::HashType;
use crate::pk_cache::PkeyParams;
use crate::pk_cache::ProvingKeyCache;

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
    pub fn new(name: &str, nb: usize, k: usize, instance_size: Vec<u32>, hashtype: HashType) -> Self {
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
        println!("write proof load info {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write(json.as_bytes()).unwrap();
    }

    pub fn load(configfile: &Path) -> Self {
        let fd = std::fs::File::open(configfile).unwrap();
        println!("read proof load info {:?}", configfile);
        serde_json::from_reader(fd).unwrap()
    }

}

impl ProofGenerationInfo {
    pub fn create_proofs<E: MultiMillerLoop>(&self, cache_folder: &Path, param_folder: &Path) {
        let params =
            load_or_build_unsafe_params::<E>(self.k, &param_folder.join(self.param.clone()));

        let pkey = read_pk_full::<E>(&params, &param_folder.join(self.circuit.clone()));

        for ((ins, wit), trans) in self.instances.iter()
                .zip(self.witnesses.clone())
                .zip(self.transcripts.clone()) {
            let instances = load_instance::<E>(&self.instance_size, &cache_folder.join(ins));

            let witnessfile = cache_folder.join(wit);
            let mut witnessreader = OpenOptions::new()
                .read(true)
                .open(witnessfile)
                .unwrap();

            let inputs_size = self.instances.iter().fold(0, |acc, x| usize::max(acc, x.len()));

            let instances: Vec<&[E::Scalar]> =
                instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

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

                    let r = transcript.finalize();
                    verify_proof(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut PoseidonRead::init(&r[..])
                    ).unwrap();
                    println!("verify halo2 proof succeed");
                    r
                },

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
                    println!("instance ... {:?}", self.instances);
                    verify_proof(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut ShaRead::<_, _, _, sha2::Sha256>::init(&r[..])
                    ).unwrap();
                    println!("verify halo2 proof succeed");
                    r
                },
            };

            let cache_file = &cache_folder.join(trans.clone());
            println!("create transcripts file {:?}", cache_file);
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
    pub fn new(name: &str, nb: usize, k: usize, instance_size: Vec<u32>, hashtype: HashType) -> Self {
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
        println!("write proof load info {:?}", cache_file);
        let json = serde_json::to_string_pretty(self).unwrap();
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write(json.as_bytes()).unwrap();
    }

    pub fn load(configfile: &Path) -> Self {
        println!("read proof load info {:?}", configfile);
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
    pub fn load_proof(cache_folder: &Path, param_folder: &Path, loadinfo: &ProofLoadInfo) -> Vec<Self> {
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

pub fn load_or_build_unsafe_params<E: MultiMillerLoop>(
    k: usize,
    cache_file: &Path,
) -> Params<E::G1Affine> {
    if Path::exists(&cache_file) {
        println!("read params K={} from {:?}", k, cache_file);
        let mut fd = std::fs::File::open(&cache_file).unwrap();
        return Params::<E::G1Affine>::read(&mut fd).unwrap();
    }

    let params = Params::<E::G1Affine>::unsafe_setup::<E>(k as u32);

    println!("write params K={} to {:?}", k, cache_file);
    let mut fd = std::fs::File::create(&cache_file).unwrap();
    params.write(&mut fd).unwrap();
    params
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> CircuitInfo<E, C> {
    pub fn new(c: C, name: String, instances: Vec<Vec<E::Scalar>>, k: usize, hash: HashType) -> Self {
        CircuitInfo {
            circuits: vec![c],
            k,
            name: name.clone(),
            proofloadinfo: ProofLoadInfo::new(
                name.as_str(),
                1,
                k,
                instances.iter().map(|x| x.len() as u32).collect::<Vec<_>>(),
                hash
            ),
            instances,
        }
    }
}

pub trait Prover<E: MultiMillerLoop> {
    fn create_proof(&self, params: &Params<E::G1Affine>, pkey: &ProvingKey<E::G1Affine>) -> Vec<u8>;
    fn create_witness(&self, cache_folder: &Path, param_folder: &Path, index: usize);
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
    pub fn exec_create_proof(&self, cache_folder: &Path, param_folder: &Path, index: usize) -> Vec<u8> {
        let params =
            load_or_build_unsafe_params::<E>(self.k, &param_folder.join(&self.proofloadinfo.param));
        let pkey = load_or_build_pkey::<E, C>(
            &params,
            self.circuits.first().unwrap(),
            &param_folder.join(self.proofloadinfo.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.name)),
        );

        store_instance(
            &self.instances,
            &cache_folder.join(self.proofloadinfo.instances[index].as_str()),
        );


        let r = self.create_proof(&params, &pkey);

        let cache_file = &cache_folder.join(&self.proofloadinfo.transcripts[index]);
        println!("create transcripts file {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write_all(&r).unwrap();

        r
    }


    pub fn create_params_pkey(
        &self,
        param_folder: &Path,
        pkcache: &ProvingKeyCache<E>,
    ) {
        use ark_std::{start_timer, end_timer};
        let key = format!("{}-{}-{}",
            self.name,
            param_folder.join(self.proofloadinfo.circuit.clone()).display(),
            param_folder.join(format!("{}.vkey.data", self.name)).display()
        );
        println!("key: {}", key);

        let timer = start_timer!(|| "--> load or create params:");
        let params =
            load_or_build_unsafe_params::<E>(self.k, &param_folder.join(self.proofloadinfo.param.clone()));
        end_timer!(timer);

        let pkey = load_or_build_pkey::<E, C>(
            &params,
            self.circuits.first().unwrap(),
            &param_folder.join(self.proofloadinfo.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.name)),
            );
        let mut cache = pkcache.pk_mem_cache.lock().unwrap();

        cache.push(
        key.clone(),
        PkeyParams::new(pkey, params)
        );
    }

    pub fn exec_create_witness_cached(
        &self,
        cache_folder: &Path,
        param_folder: &Path,
        index: usize,
        pkcache: &ProvingKeyCache<E>
    ) {
        let key = format!("{}-{}-{}",
            self.name,
            param_folder.join(self.proofloadinfo.circuit.clone()).display(),
            param_folder.join(format!("{}.vkey.data", self.name)).display()
        );
        println!("key: {}", key);

        let cache_file = &cache_folder.join(format!("{}.{}.witness.data", self.name, index));
        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&cache_file)
            .unwrap();
        let hit = || {
            let mut cache = pkcache.pk_mem_cache.lock().unwrap();
            if cache.get(&key).is_some() {
                println!("CACHE HIT");
                true
            } else {
                println!("CACHE MISS for key: {:?}", key.clone());
                false
            }
        };
        if !hit() {
            let _ = &self.create_params_pkey(
                param_folder,
                pkcache,
            );
        }

        let mut cache_lock = pkcache.pk_mem_cache.lock().unwrap();
        let p = cache_lock.get(&key.clone()).unwrap();
        create_witness(
            &p.params,
            &p.pkey,
            self.circuits.first().unwrap(),
            &self.instances.iter().map(|x| &x[..]).collect::<Vec<_>>().as_slice(),
            &mut fd
        )
        .unwrap();

        let cache_file = &cache_folder.join(format!("{}.{}.witness.data", self.name, index));
        println!("create witness file {:?}", cache_file);

    }

    pub fn exec_create_proof_cached(
        &self,
        cache_folder: &Path,
        param_folder: &Path,
        index: usize,
        pkcache: &ProvingKeyCache<E>,
    ) -> Vec<u8> {
        let key = format!("{}-{}-{}",
            self.name,
            param_folder.join(self.proofloadinfo.circuit.clone()).display(),
            param_folder.join(format!("{}.vkey.data", self.name)).display()
        );
        println!("key: {}", key);

        let hit = || {
            let mut cache = pkcache.pk_mem_cache.lock().unwrap();
            if cache.get(&key).is_some() {
                println!("CACHE HIT");
                true
            } else {
                println!("CACHE MISS for key: {:?}", key.clone());
                false
            }
        };
        if !hit() {
            let _ = &self.create_params_pkey(
                param_folder,
                pkcache,
            );
        }

        let mut cache_lock = pkcache.pk_mem_cache.lock().unwrap();
        let p = cache_lock.get(&key.clone()).unwrap();

        let r = self.create_proof(
            &p.params,
            &p.pkey,
        );

        let cache_file = &cache_folder.join(&self.proofloadinfo.transcripts[index]);
        println!("create transcripts file {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write_all(&r).unwrap();

        store_instance(
            &self.instances,
            &cache_folder.join(self.proofloadinfo.instances[index].as_str()),
        );

        r
    }
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> Prover<E> for CircuitInfo<E, C> {
    fn create_proof(&self, params: &Params<E::G1Affine>, pkey: &ProvingKey<E::G1Affine>) -> Vec<u8> {
        use ark_std::{start_timer, end_timer};

        let inputs_size = self.instances.iter().fold(0, |acc, x| usize::max(acc, x.len()));

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
                println!("instance ... {:?}", self.instances);
                verify_proof(
                    &params_verifier,
                    &pkey.get_vk(),
                    strategy,
                    &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut PoseidonRead::init(&r[..])
                ).unwrap();
                println!("verify halo2 proof with native vkey succeed");
                r
            },
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
                println!("instance ... {:?}", self.instances);
                verify_proof(
                    &params_verifier,
                    &pkey.get_vk(),
                    strategy,
                    &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha2::Sha256>::init(&r[..])
                ).unwrap();
                println!("verify halo2 proof succeed");
                r
            },
        };
        end_timer!(timer);

        r
    }

    fn create_witness(&self, cache_folder: &Path, param_folder: &Path, index: usize) {
        let params =
            load_or_build_unsafe_params::<E>(self.k, &param_folder.join(self.proofloadinfo.param.clone()));
        let pkey = load_or_build_pkey::<E, C>(
            &params,
            self.circuits.first().unwrap(),
            &param_folder.join(self.proofloadinfo.circuit.clone()),
            &param_folder.join(format!("{}.vkey.data", self.name)),
        );

        let cache_file = &cache_folder.join(format!("{}.{}.witness.data", self.name, index));

        println!("create witness file {:?}", cache_file);

        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&cache_file)
            .unwrap();
        create_witness(&params, &pkey, self.circuits.first().unwrap(), &self.instances.iter().map(|x| &x[..]).collect::<Vec<_>>().as_slice(), &mut fd).unwrap()
    }

    fn mock_proof(&self, k: u32) {
        let prover = MockProver::run(k, self.circuits.first().unwrap(), self.instances.clone()).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

pub fn load_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    param_folder: &Path,
) -> VerifyingKey<E::G1Affine> {
    println!("read vkey from {:?}", param_folder);
    let mut fd = std::fs::File::open(&param_folder).unwrap();
    VerifyingKey::read::<_, C>(&mut fd, params).unwrap()
}

pub fn load_or_build_pkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    circuit: &C,
    cache_file: &Path,
    vkey_file: &Path,
) -> ProvingKey<E::G1Affine> {
    use ark_std::{start_timer, end_timer};
    if Path::exists(&cache_file) {
        let timer = start_timer!(|| "test read info full ...");
        let pkey = read_pk_full::<E>(&params, &cache_file);
        //assert_eq!(vkey.domain, pkey.get_vk().domain);
        //assert_eq!(vkey.fixed_commitments, pkey.get_vk().fixed_commitments);
        end_timer!(timer);
        pkey
    } else {
        let vkey = keygen_vk(&params, circuit).expect("keygen_vk should not fail");
        println!("write vkey to {:?}", vkey_file);
        let mut fd = std::fs::File::create(&vkey_file).unwrap();
        vkey.write(&mut fd).unwrap();
        let pkey = keygen_pk(&params, vkey.clone(), circuit).expect("keygen_pk should not fail");
        let timer = start_timer!(|| "test storing info full ...");
        store_info_full::<E, C>(&params, &vkey, circuit, cache_file);
        end_timer!(timer);
        pkey
    }
}

fn store_info_full<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    vkey: &VerifyingKey<E::G1Affine>,
    circuit: &C,
    cache_file: &Path
) {
    println!("store vkey full to {:?}", cache_file);
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
    println!("read vkey full from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    VerifyingKey::<E::G1Affine>::fetch(&mut fd).unwrap()
}

pub(crate) fn read_pk_full<E: MultiMillerLoop>(params: &Params<E::G1Affine>, cache_file: &Path) -> ProvingKey<E::G1Affine> {
    use ark_std::{start_timer, end_timer};
    let timer = start_timer!(|| "fetch vkey full ...");
    println!("read vkey full from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    let vk = VerifyingKey::<E::G1Affine>::fetch(&mut fd).unwrap();
    end_timer!(timer);
    let timer = start_timer!(|| "fetch pk full ...");
    let pk = fetch_pk_info(params, &vk, &mut fd).unwrap();
    end_timer!(timer);
    pk
}

pub fn create_cache<E: MultiMillerLoop>() -> ProvingKeyCache<E> {
    ProvingKeyCache::<E>::new()
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
    use ark_std::{start_timer, end_timer};

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
            HashType::Poseidon
        );

        circuit_info.mock_proof(K);
        let proofloadinfo = circuit_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit1 run");
        circuit_info.create_witness(&Path::new("output"), &Path::new("params"), 0);
        circuit_info.exec_create_proof(&Path::new("output"), &Path::new("params"), 0);

        proofloadinfo.save(&Path::new("output"));
        end_timer!(timer);
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
            HashType::Poseidon
        );

        circuit_info.mock_proof(K);
        let proofloadinfo = circuit_info.proofloadinfo.clone();
        circuit_info.create_witness(&Path::new("output"), &Path::new("params"), 0);
        circuit_info.exec_create_proof(&Path::new("output"), &Path::new("params"), 0);

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
fn cache_hit_single_circuit() {
    use crate::proof::CircuitInfo;
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    use ark_std::{start_timer, end_timer};

    let pkcache = create_cache();

    const K: u32 = 22;
    {

        println!("Circuit_1 1st run:");
        let circuit1 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let circuit1_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit1,
            "test1".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit1_info.mock_proof(K);
        let proofloadinfo1 = circuit1_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit1 1st run");
        circuit1_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        circuit1_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo1.save(&Path::new("output"));
        end_timer!(timer);

        println!("Circuit_1 2nd run:");
        let circuit1 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let circuit1_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit1,
            "test1".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit1_info.mock_proof(K);
        let proofloadinfo1 = circuit1_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit1 2nd run");
        circuit1_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        circuit1_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo1.save(&Path::new("output"));
        end_timer!(timer);
    }

}

#[test]
fn cache_lru_multi_circuit() {
    use crate::proof::CircuitInfo;
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    use ark_std::{start_timer, end_timer};


    let pkcache = create_cache();

    const K: u32 = 22;
    {

        println!("Circuit_1 1st run:");
        let circuit1 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };
        let circuit1_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit1,
            "test1".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit1_info.mock_proof(K);
        let proofloadinfo1 = circuit1_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit1 1st run");
        circuit1_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        // circuit1_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo1.save(&Path::new("output"));
        end_timer!(timer);


        println!("Circuit_2:");
        let circuit2 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };
        let circuit2_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit2,
            "test2".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );


        circuit2_info.mock_proof(K);
        let proofloadinfo2 = circuit2_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit2 1st run");
        circuit2_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        // circuit2_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo2.save(&Path::new("output"));
        end_timer!(timer);


        println!("Circuit_3:");
        let circuit3 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };
        let circuit3_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit3,
            "test3".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit3_info.mock_proof(K);
        let proofloadinfo3 = circuit3_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit3 1st run");
        circuit3_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        // circuit3_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo3.save(&Path::new("output"));
        end_timer!(timer);


        println!("Circuit_4:");
        let circuit4 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };
        let circuit4_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit4,
            "test4".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit4_info.mock_proof(K);
        let proofloadinfo4 = circuit4_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit4 1st run");
        circuit4_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        // circuit4_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo4.save(&Path::new("output"));
        end_timer!(timer);


        println!("Circuit_5:");
        let circuit5 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };
        let circuit5_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit5,
            "test5".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit5_info.mock_proof(K);
        let proofloadinfo5 = circuit5_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit5 1st run");
        circuit5_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        // circuit5_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo5.save(&Path::new("output"));
        end_timer!(timer);

        println!("Circuit_6:");
        let circuit6 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };
        let circuit6_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit6,
            "test6".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit6_info.mock_proof(K);
        let proofloadinfo6 = circuit5_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit6 1st run");
        circuit6_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        // circuit6_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo6.save(&Path::new("output"));
        end_timer!(timer);

        println!("Circuit_1 2nd run:");
        let circuit1 = SimpleCircuit::<Fr> {
            a: Fr::from(100u64),
            b: Fr::from(200u64),
        };

        let circuit1_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
            circuit1,
            "test1".to_string(),
            vec![vec![Fr::from(300u64)]],
            K as usize,
            HashType::Poseidon
        );

        circuit1_info.mock_proof(K);
        let proofloadinfo1 = circuit1_info.proofloadinfo.clone();

        let timer = start_timer!(|| "--> circuit1 2nd run");
        circuit1_info.exec_create_witness_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        // circuit1_info.exec_create_proof_cached(&Path::new("output"), &Path::new("params"), 0, &pkcache);
        proofloadinfo1.save(&Path::new("output"));
        end_timer!(timer);

    }

}