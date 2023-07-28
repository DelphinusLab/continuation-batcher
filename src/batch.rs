use crate::proof::load_or_build_unsafe_params;
use crate::proof::CircuitInfo;
use crate::proof::ProofInfo;
use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuit_verifier::build_aggregate_verify_circuit;
use halo2aggregator_s::circuit_verifier::circuit::AggregatorCircuit;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2aggregator_s::native_verifier;
use std::path::Path;

pub struct BatchInfo<E: MultiMillerLoop> {
    pub proofs: Vec<ProofInfo<E>>,
    pub batch_k: usize,
    pub target_k: usize,
    pub commitment_check: Vec<[usize; 4]>,
}

impl<E: MultiMillerLoop> BatchInfo<E> {
    pub fn build_aggregate_circuit(
        &self,
        cache_folder: &Path,
        proof_name: String,
    ) -> CircuitInfo<E, AggregatorCircuit<E::G1Affine>> {
        // 1. setup params
        let params = load_or_build_unsafe_params::<E>(
            self.target_k,
            &cache_folder.join(format!("K{}.params", self.target_k)),
        );

        let mut all_proofs = vec![];
        let mut public_inputs_size = 0;
        let mut vkeys = vec![];
        let mut instances = vec![];
        for (_, proof) in self.proofs.iter().enumerate() {
            all_proofs.push((&proof.transcripts).clone());
            vkeys.push(&proof.vkey);
            //public_inputs_size += proof.instances.len() * 3;
            public_inputs_size =
                usize::max(public_inputs_size, proof.instances.iter().fold(0, |acc, x| usize::max(acc, x.len())));
            instances.push(&proof.instances);

        }
        println!("public input size {}", public_inputs_size);

        let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

        if true {
            let timer = start_timer!(|| "native verify single proof");
            for (_, proof) in self.proofs.iter().enumerate() {
                println!("proof is {:?}", proof.transcripts);
                println!("instance is {:?}", proof.instances);
                native_verifier::verify_single_proof::<E>(
                    &params_verifier,
                    &proof.vkey,
                    &proof.instances,
                    proof.transcripts.clone(),
                    TranscriptHash::Poseidon,
                );
            }
            end_timer!(timer);
        }


        // circuit multi check
        let timer = start_timer!(|| "build aggregate verify circuit");
        let (circuit, instances) = build_aggregate_verify_circuit::<E>(
            &params_verifier,
            &vkeys,
            instances,
            all_proofs,
            TranscriptHash::Poseidon,
            self.commitment_check.clone(),
        );

        end_timer!(timer);
        CircuitInfo::new(circuit, proof_name, vec![instances], self.batch_k)
    }
}
