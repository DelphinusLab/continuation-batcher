use clap::App;
use clap::AppSettings;
use std::fs;
use std::path::PathBuf;
use crate::proof::ProofLoadInfo;
use crate::proof::ProofInfo;
use crate::proof::Prover;
use halo2_proofs::pairing::bn256::Bn256;
use crate::batch::BatchInfo;
/*
use log::info;
use crate::circuits::config::init_zkwasm_runtime;
use crate::circuits::config::MIN_K;
*/

use super::command::CommandBuilder;
//use crate::exec::compile_image;
//use crate::exec::exec_aggregate_create_proof;
//use crate::exec::exec_create_proof;
use crate::exec::exec_setup;
//use crate::exec::exec_solidity_aggregate_proof;
//use crate::exec::exec_verify_aggregate_proof;
//use crate::exec::exec_verify_proof;

pub trait AppBuilder: CommandBuilder {
    const NAME: &'static str;
    const VERSION: &'static str;
    const AGGREGATE_K: u32;
    const N_PROOFS: usize;
    const MAX_PUBLIC_INPUT_SIZE: usize;

    fn app_builder<'a>() -> App<'a> {
        let app = App::new(Self::NAME)
            .version(Self::VERSION)
            .setting(AppSettings::SubcommandRequired)
            .arg(Self::output_path_arg());
        //.arg(Self::zkwasm_file_arg());

        let app = Self::append_setup_subcommand(app);
        let app = Self::append_create_aggregate_proof_subcommand(app);
        let app = Self::append_verify_aggregate_verify_subcommand(app);
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

        match top_matches.subcommand() {
            Some(("setup", _)) => {
                exec_setup(Self::AGGREGATE_K, &output_dir);
            }

            Some(("aggregate-prove", sub_matches)) => {
                let config_file = Self::parse_batch_file_arg(sub_matches);

                let proofloadinfo = ProofLoadInfo::load(&config_file);
                let batchinfo = BatchInfo::<Bn256> {
                    proofs: ProofInfo::load_proof(&output_dir, &proofloadinfo),
                    k: 21,
                    commitment_check: vec![],
                };

                let agg_circuit = batchinfo.build_aggregate_circuit(&output_dir);
                agg_circuit.create_proof(&output_dir, 0);
            }

            /*
            Some(("aggregate-verify", sub_matches)) => {
                let proof_path: PathBuf = Self::parse_proof_path_arg(&sub_matches);
                let instances_path: PathBuf = Self::parse_aggregate_instance(&sub_matches);

                exec_verify_aggregate_proof(
                    Self::AGGREGATE_K as u32,
                    &output_dir,
                    &proof_path,
                    &instances_path,
                    Self::N_PROOFS,
                );
            }

            Some(("solidity-aggregate-verifier", sub_matches)) => {
                let proof_path: PathBuf = Self::parse_proof_path_arg(&sub_matches);
                let instances_path: PathBuf = Self::parse_aggregate_instance(&sub_matches);
                let aux_only: bool = Self::parse_auxonly(&sub_matches);
                let sol_path: PathBuf = Self::parse_sol_dir_arg(&sub_matches);

                exec_solidity_aggregate_proof(
                    zkwasm_k,
                    Self::AGGREGATE_K,
                    Self::MAX_PUBLIC_INPUT_SIZE,
                    &output_dir,
                    &proof_path,
                    &sol_path,
                    &instances_path,
                    Self::N_PROOFS,
                    aux_only,
                );
            }

            */
            Some((_, _)) => todo!(),
            None => todo!(),
        }
    }
}
