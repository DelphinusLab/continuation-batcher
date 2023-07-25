use std::path::PathBuf;

use clap::arg;
use clap::value_parser;
use clap::Arg;
use clap::ArgMatches;

pub trait ArgBuilder {
    fn zkwasm_k_arg<'a>() -> Arg<'a> {
        arg!(
            -k [K] "Circuit Size K"
        )
        .value_parser(value_parser!(u32))
    }
    fn parse_zkwasm_k_arg(matches: &ArgMatches) -> Option<u32> {
        matches.get_one("K").clone().map(|v| *v)
    }

    fn batch_file_arg<'a>() -> Arg<'a> {
        arg!(
            -b --batch <BATCH_CONFIG> "Path of the batch config file"
        )
        .value_parser(value_parser!(PathBuf))
    }
    fn parse_batch_file_arg(matches: &ArgMatches) -> PathBuf {
        matches
            .get_one::<PathBuf>("batch")
            .expect("batch config is required.")
            .clone()
    }

    fn proof_path_arg<'a>() -> Arg<'a> {
        arg!(
            -p --proof <PROOF_PATH> "Path of proof."
        )
        .value_parser(value_parser!(PathBuf))
    }

    fn parse_proof_path_arg(matches: &ArgMatches) -> PathBuf {
        matches
            .get_one::<PathBuf>("proof")
            .expect("proof is required.")
            .clone()
    }


    fn output_path_arg<'a>() -> Arg<'a> {
        arg!(
            -o --output [OUTPUT_PATH] "Path of the output files.\nThe md5 of the wasm binary file is the default path if not supplied."
        ).value_parser(value_parser!(PathBuf))
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
