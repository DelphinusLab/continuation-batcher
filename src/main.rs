mod appbuilder;
mod args;
mod command;
mod exec;
mod samples;
use clap::value_parser;
use clap::Arg;
use clap::ArgAction;
use clap::ArgMatches;
use crate::appbuilder::AppBuilder;
use crate::args::ArgBuilder;
use crate::command::CommandBuilder;

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
