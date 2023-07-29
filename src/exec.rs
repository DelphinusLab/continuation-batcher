#[cfg(feature = "checksum")]
use crate::image_hasher::ImageHasher;

/*
use crate::profile::Profiler;
use crate::runtime::wasmi_interpreter::WasmRuntimeIO;
use crate::runtime::CompiledImage;
use crate::runtime::ExecutionResult;
use anyhow::Result;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::dev::MockProver;
*/
use halo2_proofs::pairing::bn256::Bn256;
/*
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::bn256::G1Affine;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuit_verifier::circuit::AggregatorCircuit;
use halo2aggregator_s::circuits::utils::load_instance;
*/
use halo2aggregator_s::circuits::utils::load_or_build_unsafe_params;
/*
use halo2aggregator_s::circuits::utils::load_or_build_vkey;
use halo2aggregator_s::circuits::utils::load_or_create_proof;
use halo2aggregator_s::circuits::utils::load_proof;
use halo2aggregator_s::circuits::utils::load_vkey;
use halo2aggregator_s::circuits::utils::run_circuit_unsafe_full_pass;
use halo2aggregator_s::circuits::utils::store_instance;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2aggregator_s::solidity_verifier::codegen::solidity_aux_gen;
use halo2aggregator_s::solidity_verifier::solidity_render;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::sha256::ShaRead;
*/
use log::info;

use std::path::PathBuf;

/*
use crate::circuits::TestCircuit;
use crate::circuits::ZkWasmCircuitBuilder;
*/

pub fn exec_setup(aggregate_k: u32, output_dir: &PathBuf) {
    info!("Setup Params and VerifyingKey");

    // Setup Aggregate Circuit Params
    {
        let params_path = &output_dir.join(format!("K{}.params", aggregate_k));

        if params_path.exists() {
            info!("Found Params with K = {} at {:?}", aggregate_k, params_path);
        } else {
            info!(
                "Create Params with K = {} to {:?}",
                aggregate_k, params_path
            );
        }

        load_or_build_unsafe_params::<Bn256>(aggregate_k, Some(params_path))
    };
}
