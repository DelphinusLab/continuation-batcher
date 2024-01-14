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
use clap::Parser;
use clap::Subcommand;
use console::style;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuit_verifier::G2AffineBaseHelper;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2aggregator_s::native_verifier;
use halo2aggregator_s::solidity_verifier::codegen::solidity_aux_gen;
use halo2ecc_s::circuit::pairing_chip::PairingChipOps;
use halo2ecc_s::context::NativeScalarEccContext;
use indicatif::style;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use log::debug;
use log::info;
use lru::LruCache;
use std::fs;
use std::fs::File;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use crate::multi_proofs::MultiProofsRequest;
use crate::request::BatchRequest;
use crate::request::Request;

const CACHE_SIZE: usize = 5;

#[derive(Subcommand)]
enum Subcommands {
    /// Build params of specified k.
    Setup {
        /// The size of circuit.
        #[clap(short)]
        k: u32,

        /// Directory to generated params.
        #[clap(short, long = "params")]
        params_dir: PathBuf,
    },
    Prove {
        /// Path of (multiple) tasks to be proved.
        #[clap(long = "proofs")]
        proofs: Vec<PathBuf>,
    },
    Batch,
    Verify,
    Solidity,
}

#[derive(Parser)]
struct CircuitBatcherApp {
    #[clap(subcommand)]
    subcommand: Subcommands,
}

pub trait AppBuilder {
    const NAME: &'static str;
    const VERSION: &'static str;
    const MAX_PUBLIC_INPUT_SIZE: usize;

    fn exec<E>() -> anyhow::Result<()>
    where
        E: MultiMillerLoop + G2AffineBaseHelper,
        NativeScalarEccContext<E::G1Affine>: PairingChipOps<E::G1Affine, E::Scalar>,
    {
        let cache_size = NonZeroUsize::new(CACHE_SIZE).unwrap();
        env_logger::init();

        let spinner_style = ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");

        let cli = CircuitBatcherApp::parse();

        match cli.subcommand {
            Subcommands::Setup { k, params_dir } => {
                fs::create_dir_all(&params_dir)?;
                let path = params_dir.join(name_of_params(k));

                println!("{} Building params...", style("[1/2]").bold().dim(),);
                let params = build_params::<E>(k);

                println!("{} Writing params...", style("[2/2]").bold().dim(),);
                let mut fd = fs::File::create(&path)?;
                params.write(&mut fd)?;

                println!(
                    "Building params done, the params is saved to {:?}, exiting...",
                    path
                );

                Ok(())
            }
            Subcommands::Prove { proofs } => {
                let progress_bar = ProgressBar::new(proofs.len() as u64);

                let mut params_cache = LruCache::new(cache_size);
                let mut proving_key_cache = LruCache::new(cache_size);

                for proof in proofs {
                    let request = Request::read(&mut File::open(&proof)?)?;

                    let loader =
                        request.into_loader::<E>(&mut params_cache, &mut proving_key_cache)?;

                    let proof = loader.as_witness_prover()?.create_proof()?;
                    request.write_proof(proof)?;

                    progress_bar.inc(1);
                }
                progress_bar.finish_and_clear();

                println!("All tasks are finished, exiting...");

                Ok(())
            }
            Subcommands::Batch => todo!(),
            Subcommands::Verify => todo!(),
            Subcommands::Solidity => todo!(),
        }

        // match top_matches.subcommand() {
        //     Some(("setup", sub_matches)) => {
        //         let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
        //         let params = build_params::<E>(k);

        //         let mut fd = fs::File::create(&param_dir.join(name_of_params(k)))?;
        //         params.write(&mut fd)?;

        //         Ok(())
        //     }

        //     Some(("prove", sub_matches)) => {
        //         let target_proving_requests = Self::parse_proof_load_info_arg(sub_matches);

        //         for request_path in target_proving_requests {
        //             let mut fd = File::open(&request_path)?;
        //             let request = MultiProofsRequest::read(&mut fd)?;

        //             request.exec_create_proof::<E>(param_dir, output_dir)?;
        //         }

        //         Ok(())
        //     }

        //     Some(("batch", sub_matches)) => {
        //         let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
        //         let hash = Self::parse_hashtype(&sub_matches);
        //         let config_files = Self::parse_proof_load_info_arg(sub_matches);
        //         let batch_script_file = Self::parse_commits_equiv_info_arg(sub_matches);
        //         let proof_name = sub_matches
        //             .get_one::<String>("name")
        //             .expect("name of the prove task is not provided");

        //         let target_proofs = config_files
        //             .iter()
        //             .map(|target_proof| Request::read(&mut File::open(target_proof)?))
        //             .collect::<Result<Vec<_>, _>>()?;
        //         let commitment_check = CommitmentCheck::read(&mut File::open(batch_script_file)?)?;
        //         let request = BatchRequest::new(k, hash, target_proofs, commitment_check);

        //         let prover = request.into_prover::<E>(param_dir, output_dir)?;

        //         let aggregator_circuit_prover = prover.build_aggregate_circuit();
        //         let proof = aggregator_circuit_prover.create_proof();

        //         // If hash type is SHA, generate aux data for solidity verifier
        //         if hash == HashType::Sha {
        //             aggregator_circuit_prover.gen_solidity_aux(
        //                 proof,
        //                 &output_dir.join(name_of_solidity_aux(proof_name)),
        //             )?;
        //         }

        //         Ok(())
        //     }

        //     Some(("verify", sub_matches)) => {
        //         let target_proving_requests = Self::parse_proof_load_info_arg(&sub_matches);
        //         let hash = Self::parse_hashtype(&sub_matches);

        //         for request_path in target_proving_requests {
        //             let request = Request::read(&mut File::open(&request_path)?)?;

        //             let loader = request.into_loader::<Bn256>(&param_dir, &output_dir)?;
        //             let verifier = loader.as_verifier()?;

        //             verifier.verify_proof()?;
        //         }

        //         Ok(())
        //     }

        //     Some(("solidity", sub_matches)) => {
        //         let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
        //         let config_file = Self::parse_proof_load_info_arg(sub_matches);
        //         let n_proofs = config_file.len() - 1;

        //         let sol_path: PathBuf = Self::parse_sol_dir_arg(&sub_matches);
        //         let sol_path_templates: PathBuf = sol_path.join("templates");
        //         let sol_path_contracts: PathBuf = sol_path.join("contracts");

        //         let target_proofs = config_file
        //             .iter()
        //             .map(|target_proof| Request::read(&mut File::open(target_proof)?))
        //             .collect::<Result<Vec<_>, _>>()?;

        //         let commits_equiv_file = Self::parse_commits_equiv_info_arg(sub_matches);
        //         let commits_equiv_info =
        //             CommitmentCheck::read(&mut File::open(commits_equiv_file)?)?;

        //         let request =
        //             BatchRequest::new(k, HashType::Sha, target_proofs, commits_equiv_info);

        //         let prover = request.into_prover::<E>(param_dir, output_dir)?;

        //         prover.generate_solidity(&sol_path_templates, &sol_path_contracts)?;

        //         Ok(())
        //     }

        //     Some((_, _)) => todo!(),
        //     None => todo!(),
        // }
    }
}
