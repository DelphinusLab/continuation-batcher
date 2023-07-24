pub mod simple;
use serde::{Deserialize, Serialize};
use ark_std::rand::rngs::OsRng;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::VerifyingKey;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use halo2aggregator_s::circuits::utils::run_circuit_unsafe_full_pass;
use std::io::Write;
use std::path::Path;
use crate::vkey::load_or_build_unsafe_params;
use crate::vkey::load_or_build_vkey;

pub struct CircuitInfo<E: MultiMillerLoop, C: Circuit<E::Scalar>> {
    pub circuit: C,
    pub name: String,
    pub instances: Vec<Vec<E::Scalar>>,
}

#[derive(Serialize, Deserialize)]
struct ProofFileInfo {
    vkey: String,
    transcripts: Vec<String>,
    instances: Vec<String>,
}

pub struct ProofInfo<E: MultiMillerLoop> {
    pub vkey: VerifyingKey<E::G1Affine>,
    pub instances: Vec<Vec<E::Scalar>>,
    pub transcripts: Vec<Vec<u8>>,
}

impl<E: MultiMillerLoop> ProofInfo<E> {
    fn load_proof(&mut self, file_info: ProofFileInfo) {
    }
}

pub struct BatchInfo <E: MultiMillerLoop> {
    pub proofs: Vec<ProofInfo<E>>,
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> CircuitInfo<E, C> {
    pub fn new(c: C, name: String, instances: Vec<Vec<E::Scalar>>) -> Self {
        CircuitInfo {
            circuit: c,
            name,
            instances,
        }
    }
}

pub trait Prover<E: MultiMillerLoop> {
    fn create_proof(self, cache_folder: &Path, k: u32) -> Vec<u8>;
    fn mock_proof(&self, k: u32);
}

impl<E: MultiMillerLoop, C: Circuit<E::Scalar>> Prover<E> for CircuitInfo<E, C> {
    fn create_proof(self, cache_folder: &Path, k: u32) -> Vec<u8> {
        let params =
            load_or_build_unsafe_params::<E>(k, Some(&cache_folder.join(format!("K{}.params", k))));
        let vkey = load_or_build_vkey::<E, C>(
            &params,
            &self.circuit,
            Some(&cache_folder.join(format!("{}.vkey.data", self.name))),
        );
        let cache_file = &cache_folder.join(format!("{}.transcript.data", self.name));
        let pkey = keygen_pk(&params, vkey, &self.circuit).expect("keygen_pk should not fail");
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

impl<E: MultiMillerLoop> BatchInfo<E> {
    pub fn aggregate_proofs(&self) {
    }
}


