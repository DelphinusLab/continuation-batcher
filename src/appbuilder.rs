use clap::App;
use clap::AppSettings;
use log::info;
use std::fs;
use std::path::PathBuf;

/*
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

        let output_dir = top_matches.get_one::<PathBuf>("output").expect("output dir is not provided");
        fs::create_dir_all(&output_dir).unwrap();

        match top_matches.subcommand() {
            Some(("setup", _)) => {
                exec_setup(
                    Self::AGGREGATE_K,
                    Self::NAME,
                    &output_dir,
                );
            }

            /*
            Some(("aggregate-prove", sub_matches)) => {
                let public_inputs: Vec<Vec<u64>> = Self::parse_aggregate_public_args(&sub_matches);
                let private_inputs: Vec<Vec<u64>> =
                    Self::parse_aggregate_private_args(&sub_matches);

                for instances in &public_inputs {
                    assert!(instances.len() <= Self::MAX_PUBLIC_INPUT_SIZE);
                }

                assert_eq!(public_inputs.len(), Self::N_PROOFS);
                assert_eq!(private_inputs.len(), Self::N_PROOFS);

                exec_aggregate_create_proof(
                    zkwasm_k,
                    Self::AGGREGATE_K,
                    Self::NAME,
                    &wasm_binary,
                    &function_name,
                    &output_dir,
                    &public_inputs,
                    &private_inputs,
                );
            }

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
