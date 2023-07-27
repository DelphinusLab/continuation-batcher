use clap::App;
use clap::AppSettings;
use std::fs;
use std::path::PathBuf;
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
            .arg(Self::output_path_arg())
            .arg(Self::zkwasm_k_arg());

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

        let k = Self::parse_zkwasm_k_arg(&top_matches).unwrap();

        match top_matches.subcommand() {
            Some(("setup", _)) => {
                exec_setup(Self::AGGREGATE_K, &output_dir);
            }

            Some(("batch", sub_matches)) => {
                let config_files = Self::parse_proof_load_info_arg(sub_matches);

                let proofs = config_files.iter().map(|config| {
                        let proofloadinfo = ProofLoadInfo::load(config);
                        ProofInfo::load_proof(&output_dir, &proofloadinfo)
                    }
                ).collect::<Vec<_>>()
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();

                let batchinfo = BatchInfo::<Bn256> {
                    proofs,
                    target_k: k as usize,
                    batch_k: 21,
                    commitment_check: vec![],
                };

                let agg_circuit = batchinfo.build_aggregate_circuit(&output_dir);
                agg_circuit.create_proof(&output_dir, 0);
            }

            Some(("verify", sub_matches)) => {
                let config_files = Self::parse_proof_load_info_arg(sub_matches);
                let proofs: Vec<ProofInfo<Bn256>> = config_files.iter().map(|config| {
                        let proofloadinfo = ProofLoadInfo::load(config);
                        ProofInfo::load_proof(&output_dir, &proofloadinfo)
                    }
                ).collect::<Vec<_>>()
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();

                let params = load_or_build_unsafe_params::<Bn256>(
                    k as usize,
                    &output_dir.join(format!("K{}.params", k)),
                );


                let mut public_inputs_size = 0;
                for proof in proofs.iter() {
                    public_inputs_size =
                        usize::max(public_inputs_size, proof.instances.iter().fold(0, |acc, x| usize::max(acc, x.len())));
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
            /*

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
