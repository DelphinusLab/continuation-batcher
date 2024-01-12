use std::path::Path;

use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::create_proof;
use halo2_proofs::plonk::create_witness;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2_proofs::poly::LagrangeCoeff;
use halo2_proofs::poly::Polynomial;
use halo2aggregator_s::solidity_verifier::codegen::solidity_aux_gen;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use halo2aggregator_s::transcript::sha256::ShaRead;
use halo2aggregator_s::transcript::sha256::ShaWrite;
use rand::rngs::OsRng;

use crate::HashType;

use super::Prover;

pub struct NativeProver<E: MultiMillerLoop, ConcreteCircuit: Circuit<E::Scalar>> {
    pub params: Params<E::G1Affine>,
    pub pkey: ProvingKey<E::G1Affine>,
    pub k: u32,
    pub circuit: ConcreteCircuit,
    pub instances: Vec<Vec<E::Scalar>>,
    pub hash_type: HashType,
}

impl<E: MultiMillerLoop, ConcreteCircuit: Circuit<E::Scalar>> NativeProver<E, ConcreteCircuit> {
    pub fn new(
        params: Params<E::G1Affine>,
        pkey: ProvingKey<E::G1Affine>,
        circuit: ConcreteCircuit,
        k: u32,
        instances: Vec<Vec<E::Scalar>>,
        hash_type: HashType,
    ) -> Self {
        NativeProver {
            params,
            pkey,
            k,
            circuit,
            instances,
            hash_type,
        }
    }
}

impl<E: MultiMillerLoop, ConcreteCircuit: Circuit<E::Scalar> + Clone> Prover<E>
    for NativeProver<E, ConcreteCircuit>
{
    fn create_proof(&self) -> Vec<u8> {
        use ark_std::end_timer;
        use ark_std::start_timer;

        let inputs_size = self
            .instances
            .iter()
            .fold(0, |acc, x| usize::max(acc, x.len()));

        let instances: Vec<&[E::Scalar]> =
            self.instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let params_verifier: ParamsVerifier<E> = self.params.verifier(inputs_size).unwrap();
        let strategy = SingleVerifier::new(&params_verifier);

        let timer = start_timer!(|| "creating proof ...");
        let r = match self.hash_type {
            HashType::Poseidon => {
                let mut transcript = PoseidonWrite::init(vec![]);
                create_proof(
                    &self.params,
                    &self.pkey,
                    &[self.circuit.clone()],
                    &[instances.as_slice()],
                    OsRng,
                    &mut transcript,
                )
                .expect("proof generation should not fail");

                let r = transcript.finalize();
                log::info!("proof created with instance: {:?}", self.instances);
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
                create_proof(
                    &self.params,
                    &self.pkey,
                    &[self.circuit.clone()],
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
        };
        end_timer!(timer);

        r
    }
}

impl<E: MultiMillerLoop, ConcreteCircuit: Circuit<E::Scalar>> NativeProver<E, ConcreteCircuit> {
    pub fn create_witness(
        &self,
        params: &Params<E::G1Affine>,
        pkey: &ProvingKey<E::G1Affine>,
    ) -> Vec<Polynomial<E::Scalar, LagrangeCoeff>> {
        log::info!("create witness file",);

        let witness = create_witness(
            &params,
            pkey,
            &self.circuit,
            &self
                .instances
                .iter()
                .map(|x| &x[..])
                .collect::<Vec<_>>()
                .as_slice(),
            todo!("delete fd"),
        );

        todo!()
    }

    pub fn mock_proof(&self) {
        let prover = MockProver::run(self.k, &self.circuit, self.instances.clone()).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    pub fn gen_solidity_aux(&self, proof: Vec<u8>, aux_file: &Path) -> anyhow::Result<()> {
        assert_eq!(self.instances.len(), 1);
        assert_eq!(self.hash_type, HashType::Sha);

        let params_verifier: ParamsVerifier<E> = self.params.verifier(self.instances[0].len())?;

        solidity_aux_gen(
            &params_verifier,
            self.pkey.get_vk(),
            &self.instances[0],
            proof,
            aux_file,
        );

        Ok(())
    }
}
