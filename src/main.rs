mod appbuilder;
mod args;
mod command;
mod exec;
mod samples;
pub mod vkey;
use clap::value_parser;
use clap::Arg;
use clap::ArgAction;
use clap::ArgMatches;
use crate::appbuilder::AppBuilder;
use crate::args::ArgBuilder;
use crate::command::CommandBuilder;
use crate::samples::Prover;

struct CircuitBatcherApp;

impl ArgBuilder for CircuitBatcherApp {
    /*
    fn parse_aggregate_private_args(matches: &ArgMatches) -> Vec<Vec<u64>> {
        vec![]
    }
    */
}
impl CommandBuilder for CircuitBatcherApp {}
impl AppBuilder for CircuitBatcherApp {
    const NAME: &'static str = "auto-circuit-batcher";
    const VERSION: &'static str = "v0.1-beta";
    const AGGREGATE_K: u32 = 21;
    const MAX_PUBLIC_INPUT_SIZE: usize = 64;

    const N_PROOFS: usize = 1;
}

/// Simple program to greet a person
fn main() {
    let app = CircuitBatcherApp::app_builder();

    CircuitBatcherApp::exec(app)
}

#[test]
fn generate_simple_circuit() {
    use halo2_proofs::pairing::bn256::Fr;
    use halo2_proofs::pairing::bn256::Bn256;
    use crate::samples::simple::SimpleCircuit;
    use crate::samples::CircuitInfo;
    use std::path::Path;

    const K: u32 = 8;
    let circuit = samples::simple::SimpleCircuit::<Fr> {
        a: Fr::from(100u64),
        b: Fr::from(200u64),
    };
    let circuit_info = CircuitInfo::<Bn256, samples::simple::SimpleCircuit<Fr>> {
        circuit,
        name: "test".to_string(),
        instances: vec![vec![Fr::from(300u64)]]
    };
    circuit_info.mock_proof(K);
    circuit_info.create_proof(&Path::new("output"), K);
}
