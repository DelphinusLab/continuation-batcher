use std::path::Path;

use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::{arithmetic::MultiMillerLoop, plonk::VerifyingKey, poly::commitment::Params};
use halo2aggregator_s::solidity_verifier::solidity_render;
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

    pub fn generate_solidity(
        &self,
        solidity_template_path: &Path,
        solidity_output_path: &Path,
    ) -> anyhow::Result<()> {
        // Why 12?
        let max_public_inputs_size = 12;

        let target_params_verifier: ParamsVerifier<E> =
            self.target_params.verifier(max_public_inputs_size).unwrap();

        let public_inputs_size = 3 * (self.target_proofs.len() + self.expose.len());

        let agg_params_verifier = self.batch_params.verifier(public_inputs_size).unwrap();

        let vkey = &self.target_proofs[0].vkey;
        let instances = &self.target_proofs[0].instances[0];
        assert_eq!(
            instances.len(),
            1,
            "only support one instance column for target circuit now."
        );
        let proof = self.target_proofs[0].transcripts.clone();

        solidity_render(
            &(solidity_template_path.to_str().unwrap().to_owned() + "/*"),
            solidity_output_path.to_str().unwrap(),
            vec![(
                "AggregatorConfig.sol.tera".to_owned(),
                "AggregatorConfig.sol".to_owned(),
            )],
            "AggregatorVerifierStepStart.sol.tera",
            "AggregatorVerifierStepEnd.sol.tera",
            |i| format!("AggregatorVerifierStep{}.sol", i + 1),
            &target_params_verifier,
            &agg_params_verifier,
            vkey,
            instances,
            proof,
        );

        Ok(())
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
