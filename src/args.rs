use std::path::PathBuf;

use clap::arg;
use clap::value_parser;
use clap::Arg;
use clap::ArgAction;
use clap::ArgMatches;
use serde::{Deserialize, Serialize};

#[derive(clap::ArgEnum, Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum HashType {
    Poseidon,
    Sha,
}


pub trait ArgBuilder {
    fn hashtype<'a>() -> Arg<'a> {
        arg!(-c --challenge<CHALLENGE_HASH_TYPE>... "HashType of Challenge")
            .max_values(1)
            .value_parser(value_parser!(HashType))
    }

    fn parse_hashtype(matches: &ArgMatches) -> HashType {
        matches
            .get_one::<HashType>("challenge")
            .expect("challenge hashtype is required")
            .clone()
    }

    fn zkwasm_k_arg<'a>() -> Arg<'a> {
        arg!(
            -k [K] "Circuit Size K"
        )
        .value_parser(value_parser!(u32))
    }
    fn parse_zkwasm_k_arg(matches: &ArgMatches) -> Option<u32> {
        matches.get_one("K").clone().map(|v| *v)
    }

    fn proof_load_info_arg<'a>() -> Arg<'a> {
        Arg::new("info")
            .long("info")
            .value_parser(value_parser!(PathBuf))
            .action(ArgAction::Append)
            .help("Path of the batch config files")
            .min_values(1)
    }
    fn parse_proof_load_info_arg(matches: &ArgMatches) -> Vec<PathBuf> {
        matches
            .get_many::<PathBuf>("info")
            .expect("proof loading info(s) is required.")
            .cloned()
            .collect::<Vec<_>>()
    }

    fn commits_info_arg<'a>() -> Arg<'a> {
        Arg::new("commits")
            .long("commits")
            .value_parser(value_parser!(PathBuf))
            .action(ArgAction::Append)
            .help("Path of the batch config files")
            .min_values(1)
            .max_values(1)
    }

    fn parse_commits_equiv_info_arg(matches: &ArgMatches) -> PathBuf {
        matches
            .get_one::<PathBuf>("commits")
            .expect("commit info file is not provided")
            .clone()
    }

    fn output_path_arg<'a>() -> Arg<'a> {
        arg!(
            -o --output [OUTPUT_PATH] "Path of the output files."
        ).value_parser(value_parser!(PathBuf))
    }

    fn param_path_arg<'a>() -> Arg<'a> {
        arg!(
            -p --param [PARAM_PATH] "Path of the param files."
        ).value_parser(value_parser!(PathBuf))
    }


    fn proof_name_arg<'a>() -> Arg<'a> {
        arg!(
            -n --name [PROOF_NAME] "name of this task."
        ).value_parser(value_parser!(String))
    }


    fn sol_dir_arg<'a>() -> Arg<'a> {
        arg!(
            -s --sol_dir [SOL_DIRECTORY] "Path of solidity directory."
        )
        .value_parser(value_parser!(PathBuf))
    }

    fn parse_sol_dir_arg(matches: &ArgMatches) -> PathBuf {
        matches
            .get_one::<PathBuf>("sol_dir")
            .map_or(PathBuf::from("sol"), |x| x.clone())
    }

    fn auxonly_arg<'a>() -> Arg<'a> {
        arg!(
            -a --auxonly "Generate aux file only."
        )
        .takes_value(false)
    }

    fn instances_path_arg<'a>() -> Arg<'a> {
        arg!(
            -i --instances <AGGREGATE_INSTANCE_PATH> "Path of aggregate instances."
        )
        .value_parser(value_parser!(PathBuf))
    }

    fn parse_aggregate_instance(matches: &ArgMatches) -> PathBuf {
        matches
            .get_one::<PathBuf>("instances")
            .expect("instances is required.")
            .clone()
    }

    fn parse_auxonly(matches: &ArgMatches) -> bool {
        matches
            .get_many::<String>("auxonly")
            .map_or(false, |_| true)
    }
}
