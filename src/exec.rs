#[cfg(feature = "checksum")]
use crate::image_hasher::ImageHasher;

/*
use crate::profile::Profiler;
use crate::runtime::wasmi_interpreter::WasmRuntimeIO;
use crate::runtime::CompiledImage;
use crate::runtime::ExecutionResult;
*/
use anyhow::Result;
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::bn256::G1Affine;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuit_verifier::circuit::AggregatorCircuit;
use halo2aggregator_s::circuits::utils::load_instance;
use halo2aggregator_s::circuits::utils::load_or_build_unsafe_params;
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
use log::info;

use std::io::Write;
use std::path::PathBuf;

/*
use crate::circuits::TestCircuit;
use crate::circuits::ZkWasmCircuitBuilder;
*/

const AGGREGATE_PREFIX: &'static str = "aggregate-circuit";

pub fn exec_setup(
    aggregate_k: u32,
    prefix: &'static str,
    output_dir: &PathBuf,
) {
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

/*

pub fn exec_aggregate_create_proof(
    zkwasm_k: u32,
    aggregate_k: u32,
    prefix: &'static str,
    wasm_binary: &Vec<u8>,
    function_name: &str,
    output_dir: &PathBuf,
    public_inputs: &Vec<Vec<u64>>,
    private_inputs: &Vec<Vec<u64>>,
) {
    assert_eq!(public_inputs.len(), private_inputs.len());

    let (circuits, instances) = public_inputs.iter().zip(private_inputs.iter()).fold(
        (vec![], vec![]),
        |(mut circuits, mut instances), (public, private)| {
            let (circuit, public_input_and_wasm_output) =
                build_circuit_with_witness(&wasm_binary, &function_name, &public, &private)
                    .unwrap();
            let mut instance = vec![];

            #[cfg(feature = "checksum")]
            instance.push(hash_image(wasm_binary, function_name));

            instance.append(
                &mut public_input_and_wasm_output
                    .iter()
                    .map(|v| Fr::from(*v))
                    .collect(),
            );

            circuits.push(circuit);
            instances.push(vec![instance]);

            (circuits, instances)
        },
    );

    let (aggregate_circuit, aggregate_instances) = run_circuit_unsafe_full_pass::<Bn256, _>(
        &output_dir.as_path(),
        prefix,
        zkwasm_k,
        circuits,
        instances,
        TranscriptHash::Poseidon,
        vec![],
        false,
    )
    .unwrap();

    run_circuit_unsafe_full_pass::<Bn256, _>(
        &output_dir.as_path(),
        AGGREGATE_PREFIX,
        aggregate_k,
        vec![aggregate_circuit],
        vec![vec![aggregate_instances]],
        TranscriptHash::Sha,
        vec![],
        true,
    );
}

pub fn exec_verify_aggregate_proof(
    aggregate_k: u32,
    output_dir: &PathBuf,
    proof_path: &PathBuf,
    instances_path: &PathBuf,
    n_proofs: usize,
) {
    let params = load_or_build_unsafe_params::<Bn256>(
        aggregate_k,
        Some(&output_dir.join(format!("K{}.params", aggregate_k))),
    );

    let proof = load_proof(&proof_path.as_path());
    let vkey = load_vkey::<Bn256, AggregatorCircuit<G1Affine>>(
        &params,
        &output_dir.join(format!("{}.{}.vkey.data", AGGREGATE_PREFIX, 0)),
    );

    let public_inputs_size: u32 = 6 + 3 * n_proofs as u32;

    let instances = load_instance::<Bn256>(&[public_inputs_size], &instances_path);

    let params_verifier: ParamsVerifier<Bn256> =
        params.verifier(public_inputs_size as usize).unwrap();
    let strategy = SingleVerifier::new(&params_verifier);

    verify_proof(
        &params_verifier,
        &vkey,
        strategy,
        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
        &mut ShaRead::<_, _, _, sha2::Sha256>::init(&proof[..]),
    )
    .unwrap();

    info!("Verifing Aggregate Proof Passed.")
}

pub fn exec_solidity_aggregate_proof(
    zkwasm_k: u32,
    aggregate_k: u32,
    max_public_inputs_size: usize,
    output_dir: &PathBuf,
    proof_path: &PathBuf,
    sol_path: &PathBuf,
    instances_path: &PathBuf,
    n_proofs: usize,
    aux_only: bool,
) {
    let zkwasm_params_verifier: ParamsVerifier<Bn256> = {
        let params = load_or_build_unsafe_params::<Bn256>(
            zkwasm_k,
            Some(&output_dir.join(format!("K{}.params", zkwasm_k))),
        );

        params.verifier(max_public_inputs_size).unwrap()
    };

    let (verifier_params_verifier, vkey, instances, proof) = {
        let public_inputs_size = 6 + 3 * n_proofs;

        let params = load_or_build_unsafe_params::<Bn256>(
            aggregate_k,
            Some(&output_dir.join(format!("K{}.params", aggregate_k))),
        );

        let params_verifier = params.verifier(public_inputs_size).unwrap();

        let vkey = load_vkey::<Bn256, AggregatorCircuit<G1Affine>>(
            &params,
            &output_dir.join(format!("{}.{}.vkey.data", AGGREGATE_PREFIX, 0)),
        );

        let instances = load_instance::<Bn256>(&[public_inputs_size as u32], &instances_path);
        let proof = load_proof(&proof_path.as_path());

        (params_verifier, vkey, instances, proof)
    };

    if !aux_only {
        let path_in = {
            let mut path = sol_path.clone();
            path.push("templates");
            path
        };
        let path_out = {
            let mut path = sol_path.clone();
            path.push("contracts");
            path
        };
        solidity_render(
            &(path_in.to_str().unwrap().to_owned() + "/\*"),
            path_out.to_str().unwrap(),
            vec![(
                "AggregatorConfig.sol.tera".to_owned(),
                "AggregatorConfig.sol".to_owned(),
            )],
            "AggregatorVerifierStepStart.sol.tera",
            "AggregatorVerifierStepEnd.sol.tera",
            |i| format!("AggregatorVerifierStep{}.sol", i + 1),
            &zkwasm_params_verifier,
            &verifier_params_verifier,
            &vkey,
            &instances[0],
            proof.clone(),
        );
    }

    solidity_aux_gen(
        &verifier_params_verifier,
        &vkey,
        &instances[0],
        proof,
        &output_dir.join(format!("{}.{}.aux.data", AGGREGATE_PREFIX, 0)),
    );
}
*/
