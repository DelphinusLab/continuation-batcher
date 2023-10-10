use crate::args::HashType;
use crate::batch::BatchInfo;
use crate::batch::CommitmentCheck;
use crate::proof::ProofLoadInfo;
use crate::proof::ProofInfo;
use crate::proof::ProvingKeyCache;
use crate::proof::ParamsCache;
use crate::proof::load_or_build_unsafe_params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::solidity_verifier::codegen::solidity_aux_gen;
use halo2aggregator_s::solidity_verifier::solidity_render;

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

pub fn generate_k_params(aggregate_k: u32, param_dir: &PathBuf, params_cache: &mut ParamsCache<Bn256>) {
    info!("Generating K Params file");

    // Setup Aggregate Circuit Params
    {
        let params_path = &param_dir.join(format!("K{}.params", aggregate_k));
        load_or_build_unsafe_params::<Bn256>(aggregate_k as usize, params_path, params_cache)
    };
}

pub fn exec_batch_proofs(
    params_cache: &mut ParamsCache<Bn256>,
    pkey_cache: &mut ProvingKeyCache<Bn256>,
    proof_name: &String,
    output_dir: &PathBuf,
    param_dir: &PathBuf,
    config_files: Vec<PathBuf>,
    commits: CommitmentCheck,
    hash: HashType,
    k: u32,
) {
    let mut target_k = None;
    let mut proofsinfo = vec![];
    let proofs = config_files.iter().map(|config| {
            let proofloadinfo = ProofLoadInfo::load(config);
            proofsinfo.push(proofloadinfo.clone());
            // target batch proof needs to use poseidon hash
            assert_eq!(proofloadinfo.hashtype, HashType::Poseidon);
            target_k = target_k.map_or(
                Some(proofloadinfo.k),
                |x| {
                    // proofs in the same batch needs to have same size
                    assert_eq!(x, proofloadinfo.k);
                    Some(x)
                }
            );
            ProofInfo::load_proof(&output_dir, &param_dir, &proofloadinfo)
        }
    ).collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let mut batchinfo = BatchInfo::<Bn256> {
        proofs,
        target_k: target_k.unwrap(),
        batch_k: k as usize,
        equivalents: vec![],
        absorb: vec![],
        expose: vec![],
    };

    batchinfo.load_commitments_check(&proofsinfo, commits);

    // setup target params
    let params = load_or_build_unsafe_params::<Bn256>(
        batchinfo.target_k,
        &param_dir.join(format!("K{}.params", batchinfo.target_k)),
        params_cache
    );

    let agg_circuit = batchinfo.build_aggregate_circuit(proof_name.clone(), hash, &params);
    agg_circuit.proofloadinfo.save(&output_dir);
    let agg_info = agg_circuit.proofloadinfo.clone();
    agg_circuit.exec_create_proof(&output_dir, &param_dir, pkey_cache, 0, params_cache);

    let proof: Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_dir, &param_dir, &agg_info);

    let public_inputs_size =
            proof[0].instances.iter().fold(0, |acc, x| usize::max(acc, x.len()));

    info!("generate aux data for proof: {:?}", agg_info);

    // setup batch params
    let params = load_or_build_unsafe_params::<Bn256>(
        agg_info.k as usize,
        &param_dir.join(format!("K{}.params", k)),
        params_cache,
    );

    let params_verifier: ParamsVerifier<Bn256> = params.verifier(public_inputs_size).unwrap();

    // generate solidity aux data
    // it only makes sense if the transcript challenge is poseidon
    if hash == HashType::Sha {
        solidity_aux_gen(
            &params_verifier,
            &proof[0].vkey,
            &proof[0].instances[0],
            proof[0].transcripts.clone(),
            &output_dir.join(format!("{}.{}.aux.data", &agg_info.name.clone(), 0)),
        );
    }
}

pub fn exec_solidity_gen(
    param_dir: &PathBuf,
    output_dir: &PathBuf,
    k: u32,
    n_proofs: usize,
    sol_path_in: &PathBuf,
    sol_path_out: &PathBuf,
    aggregate_proof_info: &ProofLoadInfo,
    batch_script: &CommitmentCheck,
    params_cache: &mut ParamsCache<Bn256>,
) {

    let max_public_inputs_size = 12;
    let aggregate_k = aggregate_proof_info.k;

    let proof_params = load_or_build_unsafe_params::<Bn256>(
        k as usize,
        &param_dir.join(format!("K{}.params", k)),
        params_cache
    );

    let proof_params_verifier: ParamsVerifier<Bn256> = proof_params.verifier(max_public_inputs_size).unwrap();

    println!("nproof {}", n_proofs);

    let public_inputs_size = 3 * (n_proofs + batch_script.expose.len());

    let agg_params = load_or_build_unsafe_params::<Bn256>(
        aggregate_k,
        &param_dir.join(format!("K{}.params", aggregate_k)),
        params_cache
    );


    let agg_params_verifier = agg_params.verifier(public_inputs_size).unwrap();

    let proof: Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_dir, &param_dir, aggregate_proof_info);

    solidity_render(
        &(sol_path_in.to_str().unwrap().to_owned() + "/*"),
        sol_path_out.to_str().unwrap(),
        vec![(
            "AggregatorConfig.sol.tera".to_owned(),
            "AggregatorConfig.sol".to_owned(),
        )],
        "AggregatorVerifierStepStart.sol.tera",
        "AggregatorVerifierStepEnd.sol.tera",
        |i| format!("AggregatorVerifierStep{}.sol", i + 1),
        &proof_params_verifier,
        &agg_params_verifier,
        &proof[0].vkey,
        &proof[0].instances[0],
        proof[0].transcripts.clone(),
    );
}

