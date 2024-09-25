
use std::path::PathBuf;
use crate::proof::ProofPieceInfo;
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
use super::vec_u8_to_vec_fr;

// TODO: adjust inputs/output if need
pub fn batch_round_1_proofs(
    params_cache: &mut ParamsCache<Bn256>,
    pkey_cache: &mut ProvingKeyCache<Bn256>,
    proof_name: &String,
    output_dir: &PathBuf,
    params_dir: &PathBuf,
    batch_k: u32,
    target_k: u32,
    input_proof: ProofPieceInfo,
    
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {

    // Load the transcript and instance bytes from the input proof
    let transcript_file_path = output_dir.join(input_proof.transcript);
    let instances_file_path = output_dir.join(input_proof.instance);

    // into bytes
    let transcript_bytes = std::fs::read(&transcript_file_path).unwrap();
    let instance_bytes = std::fs::read(&instances_file_path).unwrap();

    // repeat the input_proof 12 times
    let batch_instances = vec![transcript_bytes.clone(); 12];
    let proofs = vec![instance_bytes.clone(); 12];

    let batch_instances_fr = batch_instances.iter().map(|b| vec_u8_to_vec_fr(b)).collect::<Vec<_>>();

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
        batch_instances_fr,
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