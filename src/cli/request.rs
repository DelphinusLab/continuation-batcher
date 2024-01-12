use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
};

use circuits_batcher::{
    batch_prover::{commitment_check::CommitmentCheck, BatchProver},
    single_prover::{prover::witness::WitnessProver, verifier::SingleVerifier},
    utils::fs::load_instances,
    HashType,
};
use halo2_proofs::{
    arithmetic::MultiMillerLoop,
    helpers::AssignWitnessCollection,
    plonk::{ProvingKey, ProvingKeyBuilder},
    poly::commitment::Params,
};
use halo2aggregator_s::circuits::utils::load_proof;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Request {
    params: String,
    proving_key: String,
    k: u32,
    hash_type: HashType,

    witness: String,
    instances: String,
    transcript: String,
}

impl Request {
    pub fn read(fd: &mut File) -> io::Result<Self> {
        let request = serde_json::from_reader(fd)?;

        Ok(request)
    }

    pub fn into_loader<E: MultiMillerLoop>(
        self,
        params_dir: &Path,
        outputs_dir: &Path,
    ) -> anyhow::Result<RequestLoader<E>> {
        let params = Params::<E::G1Affine>::read(&mut File::open(params_dir.join(&self.params))?)?;
        let pkey = ProvingKeyBuilder::read(&mut File::open(params_dir.join(&self.proving_key))?)?
            .into_pkey(&params)?;

        Ok(RequestLoader {
            params,
            pkey,
            k: self.k,
            hash_type: self.hash_type,

            witness: outputs_dir.join(self.witness),
            instances: outputs_dir.join(self.instances),
            transcript: outputs_dir.join(self.transcript),
        })
    }
}

struct RequestLoader<E: MultiMillerLoop> {
    params: Params<E::G1Affine>,
    pkey: ProvingKey<E::G1Affine>,
    k: u32,
    hash_type: HashType,

    witness: PathBuf,
    instances: PathBuf,
    transcript: PathBuf,
}

impl<E: MultiMillerLoop> RequestLoader<E> {
    pub fn as_witness_prover<'a>(&'a self) -> anyhow::Result<WitnessProver<'a, E>> {
        let witness =
            AssignWitnessCollection::fetch_witness(&self.params, &mut File::open(&self.witness)?)?;

        let instances = load_instances::<E>(todo!(), &mut File::open(&self.instances)?)?;

        Ok(WitnessProver {
            params: &self.params,
            pkey: &self.pkey,
            k: self.k,
            witness,
            instances,
            hash_type: self.hash_type,
        })
    }

    pub fn as_verifier<'a>(&'a self) -> anyhow::Result<SingleVerifier<'a, E>> {
        let instances = load_instances::<E>(todo!(), &mut File::open(&self.instances)?)?;

        // Load proof from self.proof
        let proof = load_proof(&self.transcript);

        Ok(SingleVerifier {
            params: &self.params,
            vkey: self.pkey.get_vk(),
            instances,
            proof,
            hash_type: self.hash_type,
        })
    }
}

// impl Request {
//     pub fn build_prover<E: MultiMillerLoop>(
//         self,
//         params_dir: &Path,
//         output_dir: &Path,
//     ) -> anyhow::Result<WitnessProver<E>> {
//         let params = Params::<E::G1Affine>::read(&mut File::open(params_dir.join(&self.params))?)?;
//         let pkey = ProvingKeyBuilder::read(&mut File::open(params_dir.join(&self.proving_key))?)?
//             .into_pkey(&params)?;

//         let witness = AssignWitnessCollection::fetch_witness(
//             &params,
//             &mut File::open(output_dir.join(self.witness))?,
//         )?;

//         let instances =
//             load_instances::<E>(todo!(), &mut File::open(output_dir.join(self.instances))?)?;

//         Ok(WitnessProver::<E> {
//             params: &params,
//             pkey: &pkey,
//             k: self.k,
//             witness,
//             instances,
//             hash_type: self.hash_type,
//         })
//     }
// }

pub struct BatchRequest {
    target_k: u32,
    batch_k: u32,
    hash_type: HashType,
    target_proofs: Vec<Request>,
    commitment_check: CommitmentCheck,
}

impl BatchRequest {
    pub fn new(
        batch_k: u32,
        hash_type: HashType,
        target_proofs: Vec<Request>,
        commitment_check: CommitmentCheck,
    ) -> Self {
        let target_k = target_proofs[0].k;

        assert!(target_proofs.iter().all(|p| p.k == target_k));

        Self {
            target_k,
            batch_k,
            hash_type,
            target_proofs,
            commitment_check,
        }
    }

    pub fn into_prover<E: MultiMillerLoop>(
        self,
        params_dir: &Path,
        output_dir: &Path,
    ) -> anyhow::Result<BatchProver<E>> {
        todo!()
    }
}
