use clap::App;
use clap::AppSettings;
use halo2aggregator_s::solidity_verifier::solidity_render;
use std::fs;
use std::path::PathBuf;
use crate::batch::CommitmentCheck;
use crate::exec::exec_batch_proofs;
use crate::proof::ProofGenerationInfo;
use crate::proof::ProofLoadInfo;
use crate::proof::ProofInfo;
use crate::proof::load_or_build_unsafe_params;
use halo2_proofs::pairing::bn256::Bn256;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2aggregator_s::native_verifier;
use ark_std::end_timer;
use ark_std::start_timer;
use halo2_proofs::poly::commitment::ParamsVerifier;
use log::debug;
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
            .arg(Self::param_path_arg())
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

        let param_dir = top_matches
            .get_one::<PathBuf>("param")
            .expect("param dir is not provided");



        fs::create_dir_all(&output_dir).unwrap();
        println!("output dir: {:?}", output_dir);

        fs::create_dir_all(&param_dir).unwrap();
        println!("params dir: {:?}", param_dir);


        match top_matches.subcommand() {
            Some(("setup", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                generate_k_params(k, &output_dir);
            }

            Some(("prove", sub_matches)) => {
                let config_files = Self::parse_proof_load_info_arg(sub_matches);

                let proofs = config_files.iter().map(|config| {
                    ProofGenerationInfo::load(config)
                }).collect::<Vec<_>>();

                for proof in proofs {
                    proof.create_proofs::<Bn256>(output_dir, param_dir);
                }
            }

            Some(("batch", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let hash = Self::parse_hashtype(&sub_matches);
                let config_files = Self::parse_proof_load_info_arg(sub_matches);
                let batch_script_file = Self::parse_commits_equiv_info_arg(sub_matches);
                let proof_name = sub_matches
                    .get_one::<String>("name")
                    .expect("name of the prove task is not provided");

                let batch_script_info = CommitmentCheck::load(&batch_script_file);
                debug!("commits equivalent {:?}", batch_script_info);

                exec_batch_proofs(proof_name, output_dir, param_dir, config_files, batch_script_info, hash, k)
            }

            Some(("verify", sub_matches)) => {
                let config_files = Self::parse_proof_load_info_arg(&sub_matches);
                let hash = Self::parse_hashtype(&sub_matches);
                for config_file in config_files.iter() {
                    let proofloadinfo = ProofLoadInfo::load(config_file);
                    let proofs:Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_dir, &param_dir, &proofloadinfo);
                    let params = load_or_build_unsafe_params::<Bn256>(
                        proofloadinfo.k,
                        &param_dir.join(format!("K{}.params", proofloadinfo.k)),
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
                            match hash {
                                HashType::Poseidon => TranscriptHash::Poseidon,
                                HashType::Sha => TranscriptHash::Sha,
                            }
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

                let commits_equiv_file = Self::parse_commits_equiv_info_arg(sub_matches);
                let commits_equiv_info = CommitmentCheck::load(&commits_equiv_file);

                let proof_params = load_or_build_unsafe_params::<Bn256>(
                    k as usize,
                    &param_dir.join(format!("K{}.params", k)),
                );

                let proof_params_verifier: ParamsVerifier<Bn256> = proof_params.verifier(max_public_inputs_size).unwrap();

                println!("nproof {}", n_proofs);

                let public_inputs_size = 3 * (n_proofs + commits_equiv_info.expose.len());

                let agg_params = load_or_build_unsafe_params::<Bn256>(
                    aggregate_k,
                    &param_dir.join(format!("K{}.params", aggregate_k)),
                );


                let agg_params_verifier = agg_params.verifier(public_inputs_size).unwrap();

                let proof: Vec<ProofInfo<Bn256>> = ProofInfo::load_proof(&output_dir, &param_dir, &proofloadinfo);

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
