use halo2_proofs::{arithmetic::MultiMillerLoop, plonk::VerifyingKey, poly::commitment::Params};
use halo2aggregator_s::{
    circuit_verifier::{
        build_aggregate_verify_circuit, circuit::AggregatorCircuit, G2AffineBaseHelper,
    },
    circuits::utils::TranscriptHash,
};
use halo2ecc_s::{circuit::pairing_chip::PairingChipOps, context::NativeScalarEccContext};

use crate::{single_prover::prover::native::NativeProver, HashType};

pub mod commitment_check;
pub mod loader;
// use crate::args::HashType;
// use ark_std::end_timer;
// use ark_std::start_timer;
// use halo2_proofs::arithmetic::Engine;
// use halo2_proofs::arithmetic::MultiMillerLoop;
// use halo2_proofs::poly::commitment::Params;
// use halo2_proofs::poly::commitment::ParamsVerifier;
// use halo2aggregator_s::circuit_verifier::build_aggregate_verify_circuit;
// use halo2aggregator_s::circuit_verifier::circuit::AggregatorCircuit;
// use halo2aggregator_s::circuit_verifier::G2AffineBaseHelper;
// use halo2aggregator_s::circuits::utils::TranscriptHash;
// use halo2aggregator_s::native_verifier;
// use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
// use halo2ecc_s::context::NativeScalarEccContext;
// use serde::Deserialize;
// use serde::Serialize;
// use std::path::Path;

// impl<E: MultiMillerLoop + G2AffineBaseHelper> BatchInfo<E>
// where
//     NativeScalarEccContext<<E as Engine>::G1Affine>:
//         PairingChipOps<<E as Engine>::G1Affine, <E as Engine>::Scalar>,
// {
//     fn get_commitment_index(
//         &self,
//         proofsinfo: &Vec<ProofLoadInfo>,
//         cn: &CommitmentName,
//     ) -> (usize, usize) {
//         let mut idx = 0;
//         let mut column_idx = None;
//         for proofinfo in proofsinfo.iter() {
//             if proofinfo.name == cn.name {
//                 idx += cn.proof_idx;
//                 let c = self.proofs[idx]
//                     .vkey
//                     .cs
//                     .named_advices
//                     .iter()
//                     .position(|r| r.0 == cn.column_name)
//                     .unwrap();
//                 column_idx = Some(self.proofs[idx].vkey.cs.named_advices[c].1);
//                 break;
//             } else {
//                 idx += proofinfo.transcripts.len()
//             }
//         }
//         (idx, column_idx.unwrap() as usize)
//     }

//     fn get_instance_index(
//         &self,
//         proofsinfo: &Vec<ProofLoadInfo>,
//         ci: &CommitmentInInstance,
//     ) -> [usize; 3] {
//         let mut idx = 0;
//         for proofinfo in proofsinfo.iter() {
//             if proofinfo.name == ci.name {
//                 idx += ci.proof_idx;
//                 break;
//             } else {
//                 idx += proofinfo.transcripts.len()
//             }
//         }
//         [idx, 0, ci.group_idx * 3] // each commitment as instances are grouped by 3
//     }

//     pub fn load_commitments_check(
//         &mut self,
//         proofsinfo: &Vec<ProofLoadInfo>,
//         commits: CommitmentCheck,
//     ) {
//         for eqs in commits.equivalents.iter() {
//             let src = self.get_commitment_index(proofsinfo, &eqs.source);
//             let target = self.get_commitment_index(proofsinfo, &eqs.target);
//             self.equivalents.push([src.0, src.1, target.0, target.1])
//         }
//         for exp in commits.expose.iter() {
//             let s = self.get_commitment_index(proofsinfo, exp);
//             self.expose.push([s.0, s.1]);
//         }
//         for absorb in commits.absorb.iter() {
//             let s = self.get_instance_index(proofsinfo, &absorb.instance_idx);
//             let t = self.get_commitment_index(proofsinfo, &absorb.target);
//             self.absorb.push((s, [t.0, t.1]));
//         }
//     }

struct TargetProof<E: MultiMillerLoop> {
    vkey: VerifyingKey<E::G1Affine>,
    instances: Vec<Vec<E::Scalar>>,
    transcripts: Vec<u8>,
}

pub struct BatchProver<E: MultiMillerLoop> {
    target_params: Params<E::G1Affine>,
    batch_params: Params<E::G1Affine>,

    batch_k: u32,
    target_k: u32,
    hash_type: HashType,

    target_proofs: Vec<TargetProof<E>>,

    equivalents: Vec<[usize; 4]>,
    expose: Vec<[usize; 2]>,
    absorb: Vec<([usize; 3], [usize; 2])>,
}

impl<E: MultiMillerLoop + G2AffineBaseHelper> BatchProver<E>
where
    NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
{
    pub fn build_aggregate_circuit(self) -> NativeProver<E, AggregatorCircuit<E::G1Affine>> {
        let (vkey, instances, proofs) = self.target_proofs.iter().fold(
            (vec![], vec![], vec![]),
            |(mut vkey, mut instances, mut proofs), target_proof| {
                vkey.push(&target_proof.vkey);
                instances.push(&target_proof.instances);
                proofs.push(target_proof.transcripts.clone());

                (vkey, instances, proofs)
            },
        );

        let public_inputs_size = self.target_proofs.iter().fold(0, |acc, x| {
            usize::max(
                acc,
                x.instances
                    .iter()
                    .fold(0, |acc, x| usize::max(acc, x.len())),
            )
        });

        let params_verifier = self.target_params.verifier(public_inputs_size).unwrap();

        let (circuit, instances) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkey,
            instances,
            proofs,
            TranscriptHash::Poseidon,
            self.equivalents,
            self.expose,
            self.absorb,
        );

        NativeProver {
            params: self.batch_params,
            pkey: todo!(),
            k: self.batch_k,
            circuit,
            instances: vec![instances],
            hash_type: self.hash_type,
        }
    }
}

//     pub fn build_aggregate_circuit(
//         &self,
//         proof_name: String,
//         hashtype: HashType,
//         params: &Params<E::G1Affine>,
//     ) -> CircuitInfo<E, AggregatorCircuit<E::G1Affine>> {
//         let mut all_proofs = vec![];
//         let mut public_inputs_size = 0;
//         let mut vkeys = vec![];
//         let mut instances = vec![];
//         for (_, proof) in self.proofs.iter().enumerate() {
//             all_proofs.push((&proof.transcripts).clone());
//             vkeys.push(&proof.vkey);
//             //public_inputs_size += proof.instances.len() * 3;
//             public_inputs_size = usize::max(
//                 public_inputs_size,
//                 proof
//                     .instances
//                     .iter()
//                     .fold(0, |acc, x| usize::max(acc, x.len())),
//             );
//             instances.push(&proof.instances);
//         }
//         println!("public input size {}", public_inputs_size);

//         let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

//         println!("check single proof for each proof info:");
//         if true {
//             let timer = start_timer!(|| "native verify single proof");
//             for (_, proof) in self.proofs.iter().enumerate() {
//                 //println!("proof is {:?}", proof.transcripts);
//                 //println!("instance is {:?}", proof.instances);
//                 native_verifier::verify_single_proof::<E>(
//                     &params_verifier,
//                     &proof.vkey,
//                     &proof.instances,
//                     proof.transcripts.clone(),
//                     TranscriptHash::Poseidon,
//                 );
//             }
//             end_timer!(timer);
//         }
//         println!("done!");

//         println!("preparing batch circuit:");
//         for vkey in vkeys.iter() {
//             println!("vkey named advices: {:?}", vkey.cs.named_advices);
//         }
//         println!("commitment equiv: {:?}", self.equivalents);
//         println!("commitment expose: {:?}", self.expose);
//         println!("commitment absorb: {:?}", self.absorb);

//         // circuit multi check
//         let timer = start_timer!(|| "build aggregate verify circuit");
//         let (circuit, instances) = build_aggregate_verify_circuit::<E>(
//             &params_verifier,
//             &vkeys,
//             instances,
//             all_proofs,
//             TranscriptHash::Poseidon,
//             self.equivalents.clone(),
//             self.expose.clone(),
//             self.absorb.clone(),
//         );

//         end_timer!(timer);
//         CircuitInfo::new(circuit, proof_name, vec![instances], self.batch_k, hashtype)
//     }
// }
