use std::{
    fs::File,
    io::{self, Write},
    path::Path,
};

use circuits_batcher::{
    single_prover::prover::{witness::WitnessProver, Prover},
    utils::fs::load_instances,
    HashType,
};
use halo2_proofs::{
    arithmetic::MultiMillerLoop, helpers::AssignWitnessCollection, plonk::ProvingKeyBuilder,
    poly::commitment::Params,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ProofRequest {
    witness: String,
    instance: String,

    transcript_output: String,
}

#[derive(Serialize, Deserialize)]
pub struct MultiProofsRequest {
    k: u32,
    params: String,
    proving_key: String,
    hash_type: HashType,
    proofs: Vec<ProofRequest>,
}

impl MultiProofsRequest {
    pub fn read(fd: &mut File) -> io::Result<Self> {
        let request = serde_json::from_reader(fd)?;

        Ok(request)
    }
}

impl MultiProofsRequest {
    /// Read params, proving key, witness, instance, generate proof, and write proof to output
    pub fn exec_create_proof<E: MultiMillerLoop>(
        self,
        params_dir: &Path,
        output_dir: &Path,
    ) -> anyhow::Result<()> {
        let params = Params::<E::G1Affine>::read(&mut File::open(params_dir.join(&self.params))?)?;
        let pkey = ProvingKeyBuilder::read(&mut File::open(params_dir.join(&self.proving_key))?)?
            .into_pkey(&params)?;

        for proof_request in self.proofs {
            let witness = AssignWitnessCollection::fetch_witness(
                &params,
                &mut File::open(output_dir.join(proof_request.witness))?,
            )?;

            let instances = load_instances::<E>(
                todo!(),
                &mut File::open(output_dir.join(proof_request.instance))?,
            )?;

            let prover = WitnessProver::<E> {
                // FIXME: avoid clone
                params: &params,
                pkey: &pkey,
                k: self.k,
                witness,
                instances,
                hash_type: self.hash_type,
            };

            let proof = prover.create_proof();

            let mut fd = File::create(output_dir.join(proof_request.transcript_output))?;
            fd.write(&proof)?;
        }

        Ok(())
    }

    pub fn exec_verify_proof(params_dir: &Path, output_dir: &Path) -> anyhow::Result<()> {
        todo!()
    }
}
