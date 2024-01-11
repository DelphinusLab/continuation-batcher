use std::fs::File;
use std::io;

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentName {
    pub name: String,
    pub proof_idx: usize,
    pub column_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentInInstance {
    pub name: String,
    pub proof_idx: usize,
    pub group_idx: usize, // instances are grouped by 3 as commits
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentEquivPair {
    pub source: CommitmentName,
    pub target: CommitmentName,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentAbsorb {
    pub instance_idx: CommitmentInInstance,
    pub target: CommitmentName,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CommitmentCheck {
    pub equivalents: Vec<CommitmentEquivPair>,
    pub expose: Vec<CommitmentName>,
    pub absorb: Vec<CommitmentAbsorb>,
}

impl CommitmentCheck {
    pub fn load(fd: &File) -> io::Result<Self> {
        let commitment_check = serde_json::from_reader(fd)?;

        Ok(commitment_check)
    }

    pub fn write(&self, fd: &File) -> io::Result<()> {
        serde_json::to_writer_pretty(fd, self)?;

        Ok(())
    }
}
