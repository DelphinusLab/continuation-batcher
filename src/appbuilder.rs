use crate::args::HashType;
use crate::batch::CommitmentCheck;
use crate::exec::exec_batch_proofs;
use crate::exec::exec_solidity_gen;
use crate::proof::load_or_build_unsafe_params;
use crate::proof::ParamsCache;
use crate::proof::ProvingKeyCache;
use crate::proof::ProofGenerationInfo;
use crate::proof::ProofInfo;
use ark_std::end_timer;
use ark_std::start_timer;
use clap::App;
use clap::AppSettings;
use halo2_proofs::pairing::bn256::Bn256;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuits::utils::TranscriptHash;
use halo2aggregator_s::native_verifier;
use log::debug;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
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

        let params_cache = Mutex::new(ParamsCache::new(5, param_dir.clone()));
        let pkey_cache = Mutex::<ProvingKeyCache<Bn256>>::new(ProvingKeyCache::new(5, param_dir.clone()));

        fs::create_dir_all(&output_dir).unwrap();
        println!("output dir: {:?}", output_dir);

        fs::create_dir_all(&param_dir).unwrap();
        println!("params dir: {:?}", param_dir);

        match top_matches.subcommand() {
            Some(("setup", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                generate_k_params(k, &output_dir, params_cache.lock().as_mut().unwrap());
            }

            Some(("batch", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let hash = Self::parse_hashtype(&sub_matches);
                let open_schema = Self::parse_openschema(&sub_matches);
                let accumulator = Self::parse_accumulator(&sub_matches);
                let config_files = Self::parse_proof_load_info_arg(sub_matches);
                let batch_script_files = Self::parse_commits_equiv_info_arg(sub_matches);
                let cont = Self::parse_cont_arg(sub_matches);
                let proof_name = sub_matches
                    .get_one::<String>("name")
                    .expect("name of the prove task is not provided");

                let batch_script_info = batch_script_files
                    .into_iter()
                    .map(|x| CommitmentCheck::load(x.as_path()))
                    .collect::<Vec<_>>();
                debug!("commits equivalent {:?}", batch_script_info);
                exec_batch_proofs(
                    params_cache.lock().as_mut().unwrap(),
                    pkey_cache.lock().as_mut().unwrap(),
                    proof_name,
                    output_dir,
                    param_dir,
                    config_files,
                    batch_script_info,
                    hash,
                    k,
                    cont,
                    true,
                    open_schema,
                    accumulator,
                )
            }

            Some(("verify", sub_matches)) => {
                let config_files = Self::parse_proof_load_info_arg(&sub_matches);
                let hash = Self::parse_hashtype(&sub_matches);
                for config_file in config_files.iter() {
                    let proofloadinfo = ProofGenerationInfo::load(config_file);
                    let proofs: Vec<ProofInfo<Bn256>> =
                        ProofInfo::load_proof(&output_dir, &param_dir, &proofloadinfo);
                    let mut param_cache_lock = params_cache.lock(); //This is tricky. Cannot put this directly in the load_or_build_unsafe_params. Have to do this.
                    let params = load_or_build_unsafe_params::<Bn256>(
                        proofloadinfo.k,
                        &param_dir.join(format!("K{}.params", proofloadinfo.k)),
                        param_cache_lock.as_mut().unwrap(),
                    );
                    let mut public_inputs_size = 0;
                    for proof in proofs.iter() {
                        public_inputs_size = usize::max(
                            public_inputs_size,
                            proof
                                .instances
                                .iter()
                                .fold(0, |acc, x| usize::max(acc, x.len())),
                        );
                    }

                    let params_verifier: ParamsVerifier<Bn256> =
                        params.verifier(public_inputs_size).unwrap();
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
                                HashType::Keccak => TranscriptHash::Keccak,
                            },
                            true,
                            &vec![],
                        );
                    }
                    end_timer!(timer);
                }
            }

            Some(("solidity", sub_matches)) => {
                let k: u32 = Self::parse_zkwasm_k_arg(&sub_matches).unwrap();
                let config_file = Self::parse_proof_load_info_arg(sub_matches);
                let n_proofs = config_file.len() - 1;
                let sol_path: PathBuf = Self::parse_sol_dir_arg(&sub_matches);
                let hash = Self::parse_hashtype(&sub_matches);
                let hasher = match hash {
                    HashType::Poseidon => TranscriptHash::Poseidon,
                    HashType::Sha => TranscriptHash::Sha,
                    HashType::Keccak => TranscriptHash::Keccak,
                };
                let mut sol_path_templates: PathBuf = sol_path.clone();
                sol_path_templates.push("templates");
                let mut sol_path_contracts: PathBuf = sol_path.clone();
                sol_path_contracts.push("contracts");
                let proofloadinfo = ProofGenerationInfo::load(&config_file[0]);

                match hasher {
                    TranscriptHash::Keccak => {
                        exec_solidity_gen::<sha3::Keccak256>(
                            param_dir,
                            output_dir,
                            k,
                            n_proofs,
                            &sol_path_templates,
                            &sol_path_contracts,
                            &proofloadinfo,
                            params_cache.lock().as_mut().unwrap(),
                            hasher,
                        );
                    }
                    TranscriptHash::Sha => {
                        exec_solidity_gen::<sha2::Sha256>(
                            param_dir,
                            output_dir,
                            k,
                            n_proofs,
                            &sol_path_templates,
                            &sol_path_contracts,
                            &proofloadinfo,
                            params_cache.lock().as_mut().unwrap(),
                            hasher,
                        );
                    }
                    _ => {
                        panic!("Solidity generation only supports Keccak and Sha hash functions");
                    }
                }
            }
            Some((_, _)) => todo!(),
            None => todo!(),
        }
    }
}
