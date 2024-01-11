use std::fs::OpenOptions;

use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::create_witness;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::poly::LagrangeCoeff;
use halo2_proofs::poly::Polynomial;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use halo2aggregator_s::transcript::sha256::ShaRead;
use halo2aggregator_s::transcript::sha256::ShaWrite;
use rand::rngs::OsRng;

use crate::args::HashType;

pub mod loader;

pub mod native_prover;
pub mod witness_prover;

pub trait Prover<E: MultiMillerLoop> {
    fn create_proof(self, params: &Params<E::G1Affine>, pkey: &ProvingKey<E::G1Affine>) -> Vec<u8>;
}
