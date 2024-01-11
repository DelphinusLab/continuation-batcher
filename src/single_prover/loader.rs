use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2aggregator_s::circuits::utils::load_instance;
use serde::Deserialize;
use serde::Serialize;

use crate::args::HashType;

pub struct ProofInfo<E: MultiMillerLoop> {
    pub instances: Vec<Vec<E::Scalar>>,
    pub transcripts: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofInfoLoader {
    /// length of instances
    n_rows: Vec<u32>,
    /// file name of instances
    instances: String,
    /// file name of transcripts
    transcript: String,
}

impl ProofInfoLoader {
    pub fn load_proof<E: MultiMillerLoop>(
        self,
        params_dir: &Path,
        proofs_dir: &Path,
    ) -> io::Result<ProofInfo<E>> {
        let instances = load_instance::<E>(&self.n_rows, &proofs_dir.join(self.instances));

        let transcripts = {
            let mut fd = File::open(proofs_dir.join(self.transcript))?;
            let mut transcripts = Vec::new();
            fd.read_to_end(&mut transcripts)?;
            transcripts
        };

        Ok(ProofInfo {
            instances,
            transcripts,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofsInfoLoader {
    /// name of the circuit
    pub name: String,
    /// size of the circuit
    pub k: usize,
    pub hash_type: HashType,
    pub proofs: Vec<ProofInfoLoader>,
}

impl ProofsInfoLoader {
    pub fn write(&self, fd: &mut File) -> io::Result<()> {
        serde_json::to_writer(fd, self)?;

        Ok(())
    }

    pub fn read(fd: &mut File) -> io::Result<Self> {
        Ok(serde_json::from_reader(fd)?)
    }
}

impl ProofsInfoLoader {
    pub fn new(
        name: &str,
        proofs_number: usize,
        k: usize,
        n_rows: Vec<u32>,
        hash_type: HashType,
    ) -> Self {
        let mut proofs = vec![];

        for i in 0..proofs_number {
            proofs.push(ProofInfoLoader {
                n_rows: n_rows.clone(),
                instances: format!("{}.{}.instance.data", name, i),
                transcript: format!("{}.{}.transcript.data", name, i),
            })
        }

        ProofsInfoLoader {
            name: name.to_string(),
            k,
            // proving_key_builder_file_name: format!("{}.circuit.data", name),
            // params_file_name: format!("K{}.params", k),
            hash_type,
            proofs,
        }
    }

    pub fn load_proofs<E: MultiMillerLoop>(
        self,
        params_dir: &Path,
        proofs_dir: &Path,
    ) -> io::Result<Vec<ProofInfo<E>>> {
        self.proofs
            .into_iter()
            .map(|proof| proof.load_proof(params_dir, proofs_dir))
            .collect()
    }
}
