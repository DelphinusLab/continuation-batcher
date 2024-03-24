use crate::args::HashType;
use crate::args::OpenSchema;
use crate::batch::BatchInfo;
use crate::batch::CommitmentCheck;
use crate::proof::load_or_build_unsafe_params;
use crate::proof::ParamsCache;
use crate::proof::ProofGenerationInfo;
use crate::proof::ProofInfo;
use crate::proof::ProofPieceInfo;
use crate::proof::ProvingKeyCache;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuits::utils::calc_hash;
use halo2aggregator_s::circuits::utils::store_instance;
use halo2aggregator_s::circuits::utils::TranscriptHash;
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
use crate::utils::construct_merkle_records;
use ff::PrimeField;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::pairing::bn256::G1Affine;
use log::info;
use sha2::Digest;

use std::path::PathBuf;

pub fn generate_k_params(
    aggregate_k: u32,
    param_dir: &PathBuf,
    params_cache: &mut ParamsCache<Bn256>,
) {
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
    cont: Option<u32>,
    use_ecc_select_chip: bool,
    open_schema: OpenSchema,
) {
    let mut target_k = None;
    let mut proofsinfo = vec![];
    let mut proofs = config_files
        .iter()
        .map(|config| {
            let proofloadinfo = ProofGenerationInfo::load(config);
            proofsinfo.push(proofloadinfo.clone());
            // target batch proof needs to use poseidon hash
            assert_eq!(proofloadinfo.hashtype, HashType::Poseidon);
            target_k = target_k.map_or(Some(proofloadinfo.k), |x| {
                // proofs in the same batch needs to have same size
                assert_eq!(x, proofloadinfo.k);
                Some(x)
            });
            ProofInfo::load_proof(&output_dir, &param_dir, &proofloadinfo)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    proofs.reverse();

    let is_final = hash == HashType::Sha || hash == HashType::Keccak;

    let param_file = format!("K{}.params", k as usize);

    let (last_proof_gen_info, _agg_instances, shadow_instances, _) = if cont.is_some() {
        assert!(proofs.len() >= 3);

        // first round where there is no previous aggregation proof
        let mut batchinfo = BatchInfo::<Bn256> {
            proofs: vec![proofs[0].clone()],
            target_k: target_k.unwrap(),
            batch_k: k as usize,
            equivalents: vec![],
            absorb: vec![],
            expose: vec![],
            is_final: false,
        };

        let proof_piece = ProofPieceInfo::new(
            format!("{}.start", proof_name),
            0,
            batchinfo.get_agg_instance_size() as u32,
        );
        let mut proof_generation_info = ProofGenerationInfo::new(
            format!("{}.rec", proof_name).as_str(),
            batchinfo.batch_k as usize,
            HashType::Poseidon,
        );

        let (agg_proof_piece, instances, _, last_hash) = batchinfo.batch_proof(
            proof_piece,
            &param_dir.clone(),
            &output_dir.clone(),
            params_cache,
            pkey_cache,
            true,
            proof_generation_info.hashtype,
            None, // no previous agg
            open_schema,
        );

        // start recording the hash of first round
        let mut hashes = vec![last_hash];
        let mut final_hashes = vec![instances[0]]; // the first instance is the hash of the vkey of this round

        proof_generation_info.append_single_proof(agg_proof_piece);
        proof_generation_info.save(output_dir);

        // second round (1 .. k-2)
        let mut agg_proof =
            ProofInfo::load_proof(&output_dir, &param_dir, &proof_generation_info)[0].clone();

        let mut instance0 = instances[0];

        for i in 1..proofs.len() - 1 {
            println!("generate rec proofs {}", i);
            batchinfo = BatchInfo::<Bn256> {
                proofs: vec![proofs[i].clone(), agg_proof],
                target_k: target_k.unwrap(),
                batch_k: k as usize,
                equivalents: vec![],
                absorb: vec![],
                expose: vec![],
                is_final: false,
            };

            let proof_piece = ProofPieceInfo::new(
                format!("{}.rec", proof_name),
                i,
                batchinfo.get_agg_instance_size() as u32,
            );
            let (agg_proof_piece, instances, _, last_hash) = batchinfo.batch_proof(
                proof_piece,
                &param_dir.clone(),
                &output_dir.clone(),
                params_cache,
                pkey_cache,
                true,
                proof_generation_info.hashtype,
                Some(vec![(1, 0, instance0)]),
                open_schema,
            );

            instance0 = instances[0];

            proof_generation_info.append_single_proof(agg_proof_piece);
            proof_generation_info.save(output_dir);

            hashes.push(last_hash);
            final_hashes.push(instances[0]);

            agg_proof =
                ProofInfo::load_proof(&output_dir, &param_dir, &proof_generation_info)[i].clone();
        }

        proof_generation_info = ProofGenerationInfo::new(
            format!("{}.final", proof_name).as_str(),
            batchinfo.batch_k as usize,
            hash,
        );

        batchinfo = BatchInfo::<Bn256> {
            proofs: vec![proofs[proofs.len() - 1].clone(), agg_proof],
            target_k: target_k.unwrap(),
            batch_k: k as usize,
            equivalents: vec![],
            absorb: vec![],
            expose: vec![],
            is_final: true,
        };

        // Last round
        let proof_piece = ProofPieceInfo::new(
            format!("{}.final", proof_name),
            0,
            batchinfo.get_agg_instance_size() as u32,
        );

        let (agg_proof_piece, instances, shadow_instances, last_hash) = batchinfo.batch_proof(
            proof_piece,
            &param_dir.clone(),
            &output_dir.clone(),
            params_cache,
            pkey_cache,
            true,
            proof_generation_info.hashtype,
            Some(vec![(1, 0, instance0)]),
            open_schema,
        );

        proof_generation_info.append_single_proof(agg_proof_piece);
        proof_generation_info.save(output_dir);

        hashes.push(last_hash);

        let depth = cont.unwrap();
        let len = 2u32.pow(depth) as usize;

        let final_hashes_expected = calc_hash::<G1Affine>(
            hashes[0..3].try_into().unwrap(),
            hashes[0..3].try_into().unwrap(),
            len,
        );

        let mut final_hashes_merkle: Vec<[u8; 32]> = final_hashes_expected
            .iter()
            .map(|x| x.to_repr())
            .collect::<Vec<_>>();

        construct_merkle_records(
            &output_dir.join(format!("{}.{}.hashes", &proof_name, len)),
            &mut final_hashes_merkle,
            depth as usize,
        );

        (
            proof_generation_info,
            instances,
            shadow_instances,
            last_hash,
        )
    } else {
        let mut batchinfo = BatchInfo::<Bn256> {
            proofs,
            target_k: target_k.unwrap(),
            batch_k: k as usize,
            equivalents: vec![],
            absorb: vec![],
            expose: vec![],
            is_final,
        };
        batchinfo.load_commitments_check(&proofsinfo, commits);

        // Singleton batch
        let mut proof_generation_info = ProofGenerationInfo::new(
            format!("{}", proof_name).as_str(),
            batchinfo.batch_k as usize,
            hash,
        );

        let proof_piece = ProofPieceInfo::new(
            format!("{}", proof_name),
            0,
            batchinfo.get_agg_instance_size() as u32,
        );
        let (agg_proof_piece, instances, shadow_instances, last_hash) = batchinfo.batch_proof(
            proof_piece,
            &param_dir.clone(),
            &output_dir.clone(),
            params_cache,
            pkey_cache,
            use_ecc_select_chip,
            hash,
            None,
            open_schema,
        );
        proof_generation_info.append_single_proof(agg_proof_piece);
        proof_generation_info.save(output_dir);
        (
            proof_generation_info,
            instances,
            shadow_instances,
            last_hash,
        )
    };

    if hash == HashType::Sha || hash == HashType::Keccak {
        let proof: Vec<ProofInfo<Bn256>> =
            ProofInfo::load_proof(&output_dir, &param_dir, &last_proof_gen_info);

        println!("generate aux data for proof: {:?}", last_proof_gen_info);

        // setup batch params
        let params = load_or_build_unsafe_params::<Bn256>(
            last_proof_gen_info.k as usize,
            &param_dir.join(param_file),
            params_cache,
        );

        // the final instance size is 1
        let params_verifier: ParamsVerifier<Bn256> = params.verifier(1).unwrap();

        // generate solidity aux data
        // it only makes sense if the transcript challenge is poseidon
        match hash {
            HashType::Sha => {
                solidity_aux_gen::<_, sha2::Sha256>(
                    &params_verifier,
                    &proof[0].vkey,
                    &proof[0].instances[0],
                    proof[0].transcripts.clone(),
                    &output_dir.join(format!(
                        "{}.{}.aux.data",
                        &last_proof_gen_info.name.clone(),
                        0
                    )),
                );
                store_instance(
                    &vec![shadow_instances],
                    &output_dir.join(format!(
                        "{}.{}.shadowinstance.data",
                        &last_proof_gen_info.name.clone(),
                        0
                    )),
                )
            }
            HashType::Keccak => {
                solidity_aux_gen::<_, sha3::Keccak256>(
                    &params_verifier,
                    &proof[0].vkey,
                    &proof[0].instances[0],
                    proof[0].transcripts.clone(),
                    &output_dir.join(format!(
                        "{}.{}.aux.data",
                        &last_proof_gen_info.name.clone(),
                        0
                    )),
                );
                store_instance(
                    &vec![shadow_instances],
                    &output_dir.join(format!(
                        "{}.{}.shadowinstance.data",
                        &last_proof_gen_info.name.clone(),
                        0
                    )),
                )
            }
            HashType::Poseidon => unreachable!(),
        }
    }
}

pub fn exec_solidity_gen<D: Digest + Clone>(
    param_dir: &PathBuf,
    output_dir: &PathBuf,
    k: u32,
    n_proofs: usize,
    sol_path_in: &PathBuf,
    sol_path_out: &PathBuf,
    aggregate_proof_info: &ProofGenerationInfo,
    params_cache: &mut ParamsCache<Bn256>,
    hasher: TranscriptHash,
) {
    let proof_params = load_or_build_unsafe_params::<Bn256>(
        k as usize,
        &param_dir.join(format!("K{}.params", k)),
        params_cache,
    );

    let proof_params_verifier: ParamsVerifier<Bn256> = proof_params.verifier(1).unwrap();

    println!("nproof {}", n_proofs);

    let proof: Vec<ProofInfo<Bn256>> =
        ProofInfo::load_proof(&output_dir, &param_dir, aggregate_proof_info);

    solidity_render::<_, D>(
        &(sol_path_in.to_str().unwrap().to_owned() + "/*"),
        sol_path_out.to_str().unwrap(),
        vec![(
            "AggregatorConfig.sol.tera".to_owned(),
            "AggregatorConfig.sol".to_owned(),
        )],
        "AggregatorVerifierStepStart.sol.tera",
        "AggregatorVerifierStepEnd.sol.tera",
        |i| format!("AggregatorVerifierStep{}.sol", i + 1),
        hasher,
        &proof_params_verifier,
        &proof[0].vkey,
        &proof[0].instances[0],
        proof[0].transcripts.clone(),
    );
}
