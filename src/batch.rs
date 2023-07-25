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
use std::path::Path;

pub struct BatchInfo<E: MultiMillerLoop> {
    pub proofs: Vec<ProofInfo<E>>,
    pub k: usize,
    pub commitment_check: Vec<[usize; 4]>,
}

impl<E: MultiMillerLoop> BatchInfo<E> {
    pub fn build_aggregate_circuit(
        &self,
        cache_folder: &Path,
    ) -> CircuitInfo<E, AggregatorCircuit<E::G1Affine>> {
        // 1. setup params
        let params = load_or_build_unsafe_params::<E>(
            self.k,
            &cache_folder.join(format!("K{}.params", self.k)),
        );

        let mut all_proofs = vec![];
        let mut public_inputs_size = 6;
        let mut vkeys = vec![];
        let mut instances = vec![];
        for (_, proof) in self.proofs.iter().enumerate() {
            all_proofs.push((&proof.transcripts).clone());
            vkeys.push(&proof.vkey);
            public_inputs_size += proof.instances.len() * 3;
            instances.push(&proof.instances);
        }

        let params_verifier: ParamsVerifier<E> = params.verifier(public_inputs_size).unwrap();

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
        CircuitInfo::new(circuit, "aggregator".to_string(), vec![instances], self.k)
    }
}
