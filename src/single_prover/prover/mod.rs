use halo2_proofs::arithmetic::MultiMillerLoop;

pub mod native;
pub mod witness;

pub trait Prover<E: MultiMillerLoop> {
    fn create_proof(&self) -> anyhow::Result<Vec<u8>>;
}
