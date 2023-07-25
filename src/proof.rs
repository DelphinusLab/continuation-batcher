use crate::vkey::read_vkey;
use crate::vkey::write_vkey;
use ark_std::rand::rngs::OsRng;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2aggregator_s::circuits::utils::load_instance;
use halo2aggregator_s::circuits::utils::load_proof;
use halo2aggregator_s::circuits::utils::run_circuit_unsafe_full_pass;
use halo2aggregator_s::circuits::utils::store_instance;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use std::io::Write;
use std::path::Path;

#[derive(Clone)]
pub struct ProofLoadInfo {
    pub vkey: String,
    pub instance_size: Vec<u32>,
    pub transcripts: Vec<String>,
    pub instances: Vec<String>,
    pub param: String,
}

impl ProofLoadInfo {
    pub fn new(name: &str, nb: usize, k: usize, instance_size: Vec<u32>) -> Self {
        let mut transcripts = vec![];
        let mut instances = vec![];
        for i in 0..nb {
            transcripts.push(format!("{}.{}.transcript.data", name, i));
            instances.push(format!("{}.{}.instance.data", name, i));
        }
        ProofLoadInfo {
            vkey: format!("{}.vkeyfull.data", name),
            transcripts,
            instances,
            instance_size,
            param: format!("K{}.param", k),
        }
    }
}

pub struct CircuitInfo<E: MultiMillerLoop, C: Circuit<E::Scalar>> {
    pub circuit: C,
    pub name: String,
    pub k: usize,
    pub proofloadinfo: ProofLoadInfo,
    pub instances: Vec<Vec<E::Scalar>>,
}

pub struct ProofInfo<E: MultiMillerLoop> {
    pub vkey: VerifyingKey<E::G1Affine>,
    pub instances: Vec<Vec<E::Scalar>>,
    pub transcripts: Vec<u8>,
}

impl<E: MultiMillerLoop> ProofInfo<E> {
    pub fn load_proof(cache_folder: &Path, loadinfo: &ProofLoadInfo) -> Vec<Self> {
        let mut proofs = vec![];
        for (ins, trans) in loadinfo.instances.iter().zip(loadinfo.transcripts.clone()) {
            let vkey = read_vkey_full::<E>(&cache_folder.join(loadinfo.vkey.clone()));
            let instances = load_instance::<E>(&loadinfo.instance_size, &cache_folder.join(ins));
            let transcripts = load_proof(&cache_folder.join(trans));
            proofs.push(ProofInfo {
                vkey,
                instances,
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
    pub fn new(c: C, name: String, instances: Vec<Vec<E::Scalar>>, k: usize) -> Self {
        CircuitInfo {
            circuit: c,
            k,
            name: name.clone(),
            proofloadinfo: ProofLoadInfo::new(
                name.as_str(),
                1,
                k,
                instances.iter().map(|x| x.len() as u32).collect::<Vec<_>>(),
            ),
            instances,
        }
    }
}

pub trait Prover<E: MultiMillerLoop> {
    fn create_proof(self, cache_folder: &Path, k: usize) -> Vec<u8>;
    fn mock_proof(&self, k: u32);
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> Prover<E> for CircuitInfo<E, C> {
    fn create_proof(self, cache_folder: &Path, index: usize) -> Vec<u8> {
        let params =
            load_or_build_unsafe_params::<E>(self.k, &cache_folder.join(self.proofloadinfo.param));
        let vkey = load_or_build_vkey::<E, C>(
            &params,
            &self.circuit,
            &cache_folder.join(format!("{}.vkey.data", self.name)),
        );

        store_instance(
            &self.instances,
            &cache_folder.join(self.proofloadinfo.instances[index].as_str()),
        );

        store_vkey_full::<E>(&vkey, &cache_folder.join(self.proofloadinfo.vkey.clone()));
        let vkey2 = read_vkey_full::<E>(&cache_folder.join(self.proofloadinfo.vkey));
        assert_eq!(vkey.domain, vkey2.domain);
        assert_eq!(vkey.fixed_commitments, vkey2.fixed_commitments);
        // assert_eq!(vkey.permutation, vkey2.permutation);

        let pkey = keygen_pk(&params, vkey2, &self.circuit).expect("keygen_pk should not fail");
        let mut transcript = PoseidonWrite::init(vec![]);
        let instances: Vec<&[E::Scalar]> =
            self.instances.iter().map(|x| &x[..]).collect::<Vec<_>>();
        create_proof(
            &params,
            &pkey,
            &[self.circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let r = transcript.finalize();
        let cache_file = &cache_folder.join(self.proofloadinfo.transcripts[index].clone());
        println!("create file {:?}", cache_file);
        let mut fd = std::fs::File::create(&cache_file).unwrap();
        fd.write_all(&r).unwrap();
        r
    }

    fn mock_proof(&self, k: u32) {
        let prover = MockProver::run(k, &self.circuit, self.instances.clone()).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

fn load_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    cache_file: &Path,
) -> VerifyingKey<E::G1Affine> {
    println!("read vkey from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    VerifyingKey::read::<_, C>(&mut fd, params).unwrap()
}

fn load_or_build_vkey<E: MultiMillerLoop, C: Circuit<E::Scalar>>(
    params: &Params<E::G1Affine>,
    circuit: &C,
    cache_file: &Path,
) -> VerifyingKey<E::G1Affine> {
    if Path::exists(&cache_file) {
        return load_vkey::<E, C>(params, &cache_file);
    }

    let verify_circuit_vk = keygen_vk(&params, circuit).expect("keygen_vk should not fail");

    println!("write vkey to {:?}", cache_file);
    let mut fd = std::fs::File::create(&cache_file).unwrap();
    verify_circuit_vk.write(&mut fd).unwrap();

    verify_circuit_vk
}

fn store_vkey_full<E: MultiMillerLoop>(vkey: &VerifyingKey<E::G1Affine>, cache_file: &Path) {
    println!("store vkey full to {:?}", cache_file);
    let mut fd = std::fs::File::create(&cache_file).unwrap();
    write_vkey(vkey, &mut fd).unwrap();
}

pub(crate) fn read_vkey_full<E: MultiMillerLoop>(cache_file: &Path) -> VerifyingKey<E::G1Affine> {
    println!("read vkey full from {:?}", cache_file);
    let mut fd = std::fs::File::open(&cache_file).unwrap();
    read_vkey(&mut fd).unwrap()
}
