use std::fs::File;
use std::io;

use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::create_proof_from_witness;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::poly::LagrangeCoeff;
use halo2_proofs::poly::Polynomial;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use halo2aggregator_s::transcript::sha256::ShaRead;
use halo2aggregator_s::transcript::sha256::ShaWrite;
use rand::rngs::OsRng;
use serde::Deserialize;
use serde::Serialize;

use crate::HashType;

use super::Prover;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofGenerationInfo {
    pub proving_key_builder_filename: String,
    pub k: usize,
    pub instance_size: Vec<u32>,
    pub witnesses: Vec<String>,
    pub instances: Vec<String>,
    pub transcripts: Vec<String>,
    pub param: String,
    pub name: String,
    pub hashtype: HashType,
}

impl ProofGenerationInfo {
    pub fn new(
        name: &str,
        nb: usize,
        k: usize,
        instance_size: Vec<u32>,
        hashtype: HashType,
    ) -> Self {
        let mut witnesses = vec![];
        let mut instances = vec![];
        let mut transcripts = vec![];
        for i in 0..nb {
            witnesses.push(format!("{}.{}.witness.data", name, i));
            instances.push(format!("{}.{}.instance.data", name, i));
            transcripts.push(format!("{}.{}.transcripts.data", name, i));
        }
        ProofGenerationInfo {
            name: name.to_string(),
            proving_key_builder_filename: format!("{}.circuit.data", name),
            k,
            witnesses,
            instances,
            transcripts,
            instance_size,
            param: format!("K{}.params", k),
            hashtype,
        }
    }

    pub fn write(&self, fd: &mut File) -> io::Result<()> {
        // let cache_file = cache_folder.join(format!("{}.loadinfo.json", &self.name));
        // let json = serde_json::to_string_pretty(self).unwrap();
        // log::info!("write proof load info {:?}", cache_file);
        // let mut fd = std::fs::File::create(&cache_file).unwrap();
        // fd.write(json.as_bytes()).unwrap();
        serde_json::to_writer(fd, self)?;

        Ok(())
    }

    pub fn read(fd: &mut File) -> io::Result<Self> {
        // let fd = std::fs::File::open(configfile).unwrap();
        // log::info!("read proof load info {:?}", configfile);
        let info = serde_json::from_reader(fd)?;

        Ok(info)
    }
}

pub struct WitnessProver<'a, E: MultiMillerLoop> {
    pub params: &'a Params<E::G1Affine>,
    pub pkey: &'a ProvingKey<E::G1Affine>,
    pub k: u32,
    pub witness: Vec<Polynomial<E::Scalar, LagrangeCoeff>>,
    pub instances: Vec<Vec<E::Scalar>>,
    pub hash_type: HashType,
}

impl<'a, E: MultiMillerLoop> Prover<E> for WitnessProver<'a, E> {
    fn create_proof(&self) -> Vec<u8> {
        let inputs_size = self
            .instances
            .iter()
            .fold(0, |acc, x| usize::max(acc, x.len()));

        let instances: Vec<&[E::Scalar]> =
            self.instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let params_verifier: ParamsVerifier<E> = self.params.verifier(inputs_size).unwrap();
        let strategy = SingleVerifier::new(&params_verifier);

        match self.hash_type {
            HashType::Poseidon => {
                let mut transcript = PoseidonWrite::init(vec![]);
                create_proof_from_witness(
                    &self.params,
                    &self.pkey,
                    vec![self.witness.clone()],
                    &[instances.as_slice()],
                    OsRng,
                    &mut transcript,
                )
                .expect("proof generation should not fail");
                log::info!("proof created with instance ... {:?}", self.instances);

                let r = transcript.finalize();
                verify_proof(
                    &params_verifier,
                    &self.pkey.get_vk(),
                    strategy,
                    &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut PoseidonRead::init(&r[..]),
                )
                .unwrap();
                log::info!("verify halo2 proof succeed");
                r
            }

            HashType::Sha => {
                let mut transcript = ShaWrite::<_, _, _, sha2::Sha256>::init(vec![]);
                create_proof_from_witness(
                    &self.params,
                    &self.pkey,
                    vec![self.witness.clone()],
                    &[instances.as_slice()],
                    OsRng,
                    &mut transcript,
                )
                .expect("proof generation should not fail");

                let r = transcript.finalize();
                log::info!("proof created with instance ... {:?}", self.instances);
                verify_proof(
                    &params_verifier,
                    &self.pkey.get_vk(),
                    strategy,
                    &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                    &mut ShaRead::<_, _, _, sha2::Sha256>::init(&r[..]),
                )
                .unwrap();
                log::info!("verify halo2 proof succeed");
                r
            }
        }
    }
}
