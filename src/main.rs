mod appbuilder;
mod args;
pub mod batch;
mod command;
mod exec;
pub mod proof;
mod samples;
pub mod vkey;
use crate::appbuilder::AppBuilder;
use crate::args::ArgBuilder;
use crate::command::CommandBuilder;
use clap::value_parser;
use clap::Arg;
use clap::ArgAction;
use clap::ArgMatches;

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
fn batch_single_circuit() {
    use crate::batch::BatchInfo;
    use crate::proof::CircuitInfo;
    use crate::proof::ProofInfo;
    use crate::proof::Prover;
    use crate::samples::simple::SimpleCircuit;
    use halo2_proofs::pairing::bn256::Bn256;
    use halo2_proofs::pairing::bn256::Fr;
    use std::path::Path;

    const K: u32 = 8;
    let circuit = samples::simple::SimpleCircuit::<Fr> {
        a: Fr::from(100u64),
        b: Fr::from(200u64),
    };
    let circuit_info = CircuitInfo::<Bn256, SimpleCircuit<Fr>>::new(
        circuit,
        "test".to_string(),
        vec![vec![Fr::from(300u64)]],
        K as usize,
    );
    circuit_info.mock_proof(K);
    let proofloadinfo = circuit_info.proofloadinfo.clone();
    circuit_info.create_proof(&Path::new("output"), 0);

    let batchinfo = BatchInfo::<Bn256> {
        proofs: ProofInfo::load_proof(&Path::new("output"), &proofloadinfo),
        k: 21,
        commitment_check: vec![],
    };

    let agg_circuit = batchinfo.build_aggregate_circuit(&Path::new("output"));
    agg_circuit.create_proof(&Path::new("output"), 0);
}
