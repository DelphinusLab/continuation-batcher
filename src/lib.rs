use serde::{Deserialize, Serialize};

pub mod batch;
pub mod batch_prover;
pub mod names;
pub mod proof;
pub mod samples;
pub mod setup;
pub mod single_prover;
pub mod utils;

#[derive(clap::ArgEnum, Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum HashType {
    Poseidon,
    Sha,
}
