use ark_std::end_timer;
use ark_std::start_timer;
use circuits_batcher::batch_prover::commitment_check::CommitmentCheck;
use circuits_batcher::names::name_of_params;
use circuits_batcher::names::name_of_solidity_aux;
use circuits_batcher::setup::params::build_params;
use circuits_batcher::single_prover::prover::Prover;
use circuits_batcher::single_prover::verifier::Verifier;
use circuits_batcher::HashType;
use clap::App;
use clap::AppSettings;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2aggregator_s::native_verifier;
use halo2aggregator_s::solidity_verifier::codegen::solidity_aux_gen;
use log::debug;
use std::fs;
use std::fs::File;
use std::path::PathBuf;

use crate::command::CommandBuilder;
use crate::multi_proofs::MultiProofsRequest;
use crate::request::BatchRequest;
use crate::request::Request;

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

    fn exec(command: App) -> anyhow::Result<()> {
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
                let params = build_params(k);

                let mut fd = fs::File::create(&param_dir.join(name_of_params(k)))?;
                params.write(&mut fd)?;

                Ok(())
            }

            Some(("prove", sub_matches)) => {
                let target_proving_requests = Self::parse_proof_load_info_arg(sub_matches);

                for request_path in target_proving_requests {
                    let mut fd = File::open(&request_path)?;
                    let request = MultiProofsRequest::read(&mut fd)?;

                    request.exec_create_proof(param_dir, output_dir)?;
                }

                Ok(())
            }

            Some(("batch", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let hash = Self::parse_hashtype(&sub_matches);
                let config_files = Self::parse_proof_load_info_arg(sub_matches);
                let batch_script_file = Self::parse_commits_equiv_info_arg(sub_matches);
                let proof_name = sub_matches
                    .get_one::<String>("name")
                    .expect("name of the prove task is not provided");

                let target_proofs = config_files
                    .iter()
                    .map(|target_proof| Request::read(&mut File::open(target_proof)?))
                    .collect::<Result<Vec<_>, _>>()?;
                let commitment_check = CommitmentCheck::read(&mut File::open(batch_script_file)?)?;
                let request = BatchRequest::new(k, hash, target_proofs, commitment_check);

                let prover = request.into_prover(param_dir, output_dir)?;

                let aggregator_circuit_prover = prover.build_aggregate_circuit();
                let proof = aggregator_circuit_prover.create_proof();

                // If hash type is SHA, generate aux data for solidity verifier
                if hash == HashType::Sha {
                    aggregator_circuit_prover.gen_solidity_aux(
                        proof,
                        &output_dir.join(name_of_solidity_aux(proof_name)),
                    )?;
                }

                Ok(())
            }

            Some(("verify", sub_matches)) => {
                let target_proving_requests = Self::parse_proof_load_info_arg(&sub_matches);
                let hash = Self::parse_hashtype(&sub_matches);

                for request_path in target_proving_requests {
                    let request = Request::read(&mut File::open(&request_path)?)?;

                    let verifier = request
                        .into_loader::<Bn256>(&param_dir, &output_dir)?
                        .as_verifier()?;

                    verifier.verify_proof()?;
                }

                Ok(())
            }

            Some(("solidity", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let config_file = Self::parse_proof_load_info_arg(sub_matches);
                let n_proofs = config_file.len() - 1;

                let sol_path: PathBuf = Self::parse_sol_dir_arg(&sub_matches);
                let sol_path_templates: PathBuf = sol_path.join("templates");
                let sol_path_contracts: PathBuf = sol_path.join("contracts");

                let proofloadinfo = ProofLoadInfo::load(&config_file[0]);

                let commits_equiv_file = Self::parse_commits_equiv_info_arg(sub_matches);
                let commits_equiv_info =
                    CommitmentCheck::read(&mut File::open(commits_equiv_file)?)?;

                exec_solidity_gen(
                    param_dir,
                    output_dir,
                    k,
                    n_proofs,
                    &sol_path_templates,
                    &sol_path_contracts,
                    &proofloadinfo,
                    &commits_equiv_info,
                );

                Ok(())
            }

            Some((_, _)) => todo!(),
            None => todo!(),
        }
    }
}
