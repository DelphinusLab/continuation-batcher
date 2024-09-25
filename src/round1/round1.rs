
use std::path::PathBuf;
use crate::proof::ProofInfo;
use crate::round1::vec_fr_to_vec_u8;
// This file include the executing logic of Round1

use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::bn256::G1Affine;
use halo2aggregator_s::circuit_verifier::circuit::AggregatorCircuit;
use halo2aggregator_s::circuits::utils::load_vkey;

use crate::proof::load_or_build_unsafe_params;
use crate::proof::ParamsCache;
use crate::proof::ProvingKeyCache;

use super::batch_proofs;

// TODO: adjust inputs/output if need
pub fn batch_round_1_proofs(
    params_cache: &mut ParamsCache<Bn256>,
    pkey_cache: &mut ProvingKeyCache<Bn256>,
    proof_name: &String,
    output_dir: &PathBuf,
    params_dir: &PathBuf,
    batch_k: u32,
    target_k: u32,
    input_proof: Vec<ProofInfo<Bn256>>,
    
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {

    // into bytes
    let transcript_bytes = input_proof[0].transcripts.clone();

    // repeat the input_proof 12 times
    let batch_instances = vec![input_proof[0].instances[0].clone(); 12];
    let proofs = vec![transcript_bytes.clone(); 12];

    let params_file = format!("K{}.params", target_k);
    let param_file_path = params_dir.join(params_file);

    let auto_submit_params = load_or_build_unsafe_params::<Bn256>(
        target_k as usize,
        &param_file_path,
        params_cache,
    );

    let vkey_file = format!("{}.final.circuit.data.vkey.data", proof_name);
    let aggr_final_vkey_file_path = output_dir.join(vkey_file);

    // Here we need use STATIC_PKEY_CACHE as we are trying to get the PKEY for our playground aggr proofs
    let target_circuit_vkey = load_vkey::<Bn256, AggregatorCircuit<G1Affine>>(auto_submit_params, &aggr_final_vkey_file_path);

    let round_1_proof_name = "round1";
    let (transcripts, instances_fr, shadow_instances_fr, aux): (Vec<u8>, Vec<Fr>, Vec<Fr>, Vec<u8>) = batch_proofs(
        params_cache,
        pkey_cache,
        proofs,
        batch_instances,
        target_circuit_vkey,
        round_1_proof_name.to_string(),
        target_k as usize,
        batch_k as usize,
        true,
        &output_dir,
        params_dir,
    );

    let result_instances = vec_fr_to_vec_u8(&instances_fr);
    let result_shadow_instances = vec_fr_to_vec_u8(&shadow_instances_fr);
    (transcripts, result_instances, result_shadow_instances, aux)
}