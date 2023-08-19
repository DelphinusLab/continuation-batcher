use clap::App;
use clap::AppSettings;
use halo2aggregator_s::solidity_verifier::codegen::solidity_aux_gen;
use halo2aggregator_s::solidity_verifier::solidity_render;
use std::fs;
use std::path::PathBuf;
use crate::batch::CommitmentCheck;
use crate::proof::ProofGenerationInfo;
use crate::proof::ProofLoadInfo;
use crate::proof::ProofInfo;
use crate::proof::Prover;
use crate::proof::load_or_build_unsafe_params;
use halo2_proofs::pairing::bn256::Bn256;
use crate::batch::BatchInfo;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2aggregator_s::native_verifier;
use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::poly::commitment::ParamsVerifier;
use crate::args::HashType;
/*
use log::info;
*/

use super::command::CommandBuilder;
use crate::exec::generate_k_params;

pub trait AppBuilder: CommandBuilder {
    const NAME: &'static str;
    const VERSION: &'static str;
    const MAX_PUBLIC_INPUT_SIZE: usize;

    fn app_builder<'a>() -> App<'a> {
        let app = App::new(Self::NAME)
            .version(Self::VERSION)
            .setting(AppSettings::SubcommandRequired)
            .arg(Self::output_path_arg());

        let app = Self::append_params_subcommand(app);
        let app = Self::append_setup_subcommand(app);
        let app = Self::append_batch_subcommand(app);
        let app = Self::append_verify_subcommand(app);
        let app = Self::append_prove_subcommand(app);
        let app = Self::append_generate_solidity_verifier(app);
        app
    }

    fn exec(command: App) {
        env_logger::init();

        let top_matches = command.get_matches();

        let output_dir = top_matches
            .get_one::<PathBuf>("output")
            .expect("output dir is not provided");

        fs::create_dir_all(&output_dir).unwrap();
        println!("output dir: {:?}", output_dir);


        match top_matches.subcommand() {
            Some(("params", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                generate_k_params(k, &output_dir);
            }
            Some(("setup", _)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&top_matches).unwrap();

                generate_k_params(k, &output_dir);
            }

            Some(("prove", sub_matches)) => {
                let config_files = Self::parse_proof_load_info_arg(sub_matches);

                let proofs = config_files.iter().map(|config| {
                    ProofGenerationInfo::load(config)
                }).collect::<Vec<_>>();

                for proof in proofs {
                    proof.create_proofs::<Bn256>(output_dir);
                }
            }

            Some(("batch", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let hash = Self::parse_hashtype(&sub_matches);
                let config_files = Self::parse_proof_load_info_arg(sub_matches);
                let commits_equiv_file = Self::parse_commits_equiv_info_arg(sub_matches);

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
                                assert_eq!(x, proofloadinfo.k);
                                Some(x)
                            }
                        );
                        ProofInfo::load_proof(&output_dir, &proofloadinfo)
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

                let commits_equiv_info = CommitmentCheck::load(&commits_equiv_file);

                println!("commits equivalent {:?}", commits_equiv_info);

                let proof_name = sub_matches
                    .get_one::<String>("name")
                    .expect("name of the prove task is not provided");

                batchinfo.load_commitments_check(&proofsinfo, commits_equiv_info);

                let agg_circuit = batchinfo.build_aggregate_circuit(&output_dir, proof_name.clone(), hash);
                agg_circuit.proofloadinfo.save(&output_dir);
                let agg_info = agg_circuit.proofloadinfo.clone();
                agg_circuit.create_proof(&output_dir, 0);

                let proof: Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_dir, &agg_info);

                let public_inputs_size =
                        proof[0].instances.iter().fold(0, |acc, x| usize::max(acc, x.len()));

                println!("generate aux data for proof: {:?}", agg_info);

                let params = load_or_build_unsafe_params::<Bn256>(
                    agg_info.k as usize,
                    &output_dir.join(format!("K{}.params", k)),
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

            Some(("verify", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let config_files = Self::parse_proof_load_info_arg(&sub_matches);
                for config_file in config_files.iter() {
                    let proofloadinfo = ProofLoadInfo::load(config_file);
                    let proofs:Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_dir, &proofloadinfo);
                    let params = load_or_build_unsafe_params::<Bn256>(
                        proofloadinfo.k,
                        &output_dir.join(format!("K{}.params", k)),
                    );
                    let mut public_inputs_size = 0;
                    for proof in proofs.iter() {
                        public_inputs_size =
                            usize::max(public_inputs_size,
                                proof.instances.iter().fold(0, |acc, x| usize::max(acc, x.len()))
                            );
                    }

                    let params_verifier: ParamsVerifier<Bn256> = params.verifier(public_inputs_size).unwrap();
                    let timer = start_timer!(|| "native verify single proof");
                    for (_, proof) in proofs.iter().enumerate() {
                        native_verifier::verify_single_proof::<Bn256>(
                            &params_verifier,
                            &proof.vkey,
                            &proof.instances,
                            proof.transcripts.clone(),
                            TranscriptHash::Poseidon,
                        );
                    }
                    end_timer!(timer);
                }
            }

            Some(("solidity", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let max_public_inputs_size = 12;
                let config_file = Self::parse_proof_load_info_arg(sub_matches);
                let n_proofs = config_file.len() - 1;
                let sol_path: PathBuf = Self::parse_sol_dir_arg(&sub_matches);
                let proofloadinfo = ProofLoadInfo::load(&config_file[0]);
                let aggregate_k = proofloadinfo.k;

                let proof_params = load_or_build_unsafe_params::<Bn256>(
                    k as usize,
                    &output_dir.join(format!("K{}.params", k)),
                );

                let proof_params_verifier: ParamsVerifier<Bn256> = proof_params.verifier(max_public_inputs_size).unwrap();

                let public_inputs_size = 6 + 3 * n_proofs;

                let agg_params = load_or_build_unsafe_params::<Bn256>(
                    aggregate_k,
                    &output_dir.join(format!("K{}.params", aggregate_k)),
                );


                let agg_params_verifier = agg_params.verifier(public_inputs_size).unwrap();

                let proof: Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_dir, &proofloadinfo);

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
                    &(path_in.to_str().unwrap().to_owned() + "/*"),
                    path_out.to_str().unwrap(),
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

            Some((_, _)) => todo!(),
            None => todo!(),
        }
    }
}
