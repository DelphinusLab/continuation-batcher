use halo2_proofs::{arithmetic::MultiMillerLoop, plonk::VerifyingKey, poly::commitment::Params};
use halo2aggregator_s::{circuits::utils::TranscriptHash, native_verifier};

use crate::HashType;

pub trait Verifier {
    fn verify_proof(&self) -> anyhow::Result<()>;
}

pub struct SingleVerifier<'a, E: MultiMillerLoop> {
    pub params: &'a Params<E::G1Affine>,
    pub vkey: &'a VerifyingKey<E::G1Affine>,
    pub instances: Vec<Vec<E::Scalar>>,
    pub proof: Vec<u8>,
    pub hash_type: HashType,
}

impl<'a, E: MultiMillerLoop> Verifier for SingleVerifier<'a, E> {
    fn verify_proof(&self) -> anyhow::Result<()> {
        let public_inputs_size = self
            .instances
            .iter()
            .fold(0, |acc, instances| usize::max(acc, instances.len()));

        let params_verifier = self.params.verifier(public_inputs_size)?;

        native_verifier::verify_single_proof::<E>(
            &params_verifier,
            &self.vkey,
            &self.instances,
            self.proof.clone(),
            match self.hash_type {
                HashType::Poseidon => TranscriptHash::Poseidon,
                HashType::Sha => TranscriptHash::Sha,
            },
        );

        Ok(())
    }
}
