use super::ProverBackend;
use super::ProvingKeyCache;
use crate::args::HashType;
use crate::args::OpenSchema;
use crate::proof::AnyProvingKey;
use halo2_proofs::arithmetic::Engine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::helpers::Serializable;
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::verify_proof;
use halo2_proofs::plonk::verify_proof_with_shplonk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::CircuitData;
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::plonk::SingleVerifier;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;
use halo2aggregator_s::circuits::utils::ProveSchema;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use halo2aggregator_s::transcript::sha256::ShaRead;
use halo2aggregator_s::transcript::sha256::ShaWrite;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::OpenOptions;
use std::hash::Hash;
use std::marker::PhantomData;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Halo2Backend<E>(PhantomData<E>)
where
    E: std::fmt::Debug;

impl<E: MultiMillerLoop + std::fmt::Debug> ProverBackend<E> for Halo2Backend<E>
where
    <E as Engine>::G1Affine: Serialize + DeserializeOwned,
    <E as Engine>::G2Affine: Serialize + DeserializeOwned,
    <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash,
{
    type VerifierParam = VerifyingKey<E::G1Affine>;
    type ProverParam = ProvingKey<E::G1Affine>;

    fn load_vkey<C: Circuit<E::Scalar>>(
        params: &Params<E::G1Affine>,
        param_folder: &Path,
    ) -> Self::VerifierParam {
        log::info!("read vkey from {:?}", param_folder);
        let mut fd = std::fs::File::open(&param_folder).unwrap();
        VerifyingKey::read::<_, C>(&mut fd, params).unwrap()
    }

    fn load_or_build_pkey<'a, C: Circuit<E::Scalar>>(
        params: &Params<E::G1Affine>,
        circuit: &C,
        cache_file: &Path,
        vkey_file: &Path,
        pkey_cache: &'a mut ProvingKeyCache<E>,
    ) -> &'a Self::ProverParam {
        use ark_std::{end_timer, start_timer};
        let key = cache_file.to_str().unwrap().to_string();
        if pkey_cache.contains(&key) {
            log::info!("pkey find in cache. Key: {:?}", &key);
            pkey_cache.get(&key).as_halo2().unwrap()
        } else {
            log::info!("pkey not found in cache. Key: {:?}", &key);
            let pkey = if Path::exists(&cache_file) {
                let timer = start_timer!(|| "test read info full ...");
                let pkey = Self::read_pk_full(params, &cache_file);
                //assert_eq!(vkey.domain, pkey.get_vk().domain);
                //assert_eq!(vkey.fixed_commitments, pkey.get_vk().fixed_commitments);
                end_timer!(timer);
                pkey
            } else {
                let vkey = ProveSchema::UseHalo2.load_or_build_vkey::<E, C>(
                    params,
                    circuit,
                    Some(vkey_file),
                );
                let vkey = vkey.as_halo2().unwrap().clone();
                let pkey =
                    keygen_pk(&params, vkey.clone(), circuit).expect("keygen_pk should not fail");
                let timer = start_timer!(|| "test storing info full ...");
                Self::store_pk_full(&params, &pkey, &vkey, circuit, cache_file);
                end_timer!(timer);
                pkey
            };
            pkey_cache
                .push(key, AnyProvingKey::Halo2(pkey))
                .as_halo2()
                .unwrap()
        }
    }

    //todo refactor params with hyper
    fn store_pk_full<C: Circuit<E::Scalar>>(
        params: &Params<E::G1Affine>,
        _pkey: &Self::ProverParam,
        vkey: &Self::VerifierParam,
        circuit: &C,
        cache_file: &Path,
    ) {
        log::info!("store vkey full to {:?}", cache_file);
        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&cache_file)
            .unwrap();
        let data = CircuitData::new(params, vkey.clone(), circuit).unwrap();
        data.write(&mut fd).unwrap();
    }

    fn read_vkey_full(cache_file: &Path) -> Self::VerifierParam {
        log::info!("read vkey full from {:?}", cache_file);
        let mut fd = std::fs::File::open(&cache_file).unwrap();
        VerifyingKey::<E::G1Affine>::fetch(&mut fd).unwrap()
    }

    fn read_pk_full(params: &Params<E::G1Affine>, cache_file: &Path) -> Self::ProverParam {
        use ark_std::{end_timer, start_timer};
        let timer = start_timer!(|| "fetch vkey full ...");
        log::info!("read vkey full from {:?}", cache_file);
        let mut fd = std::fs::File::open(&cache_file).unwrap();
        end_timer!(timer);
        let timer = start_timer!(|| "fetch pk full ...");
        let circuit_data = CircuitData::read(&mut fd).unwrap();
        let pk = circuit_data.into_proving_key(params);
        end_timer!(timer);
        pk
    }

    fn create_proof<C: Circuit<E::Scalar>>(
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &Self::ProverParam,
        hashtype: HashType,
        schema: OpenSchema,
    ) -> Vec<u8> {
        use ark_std::{end_timer, start_timer};

        let inputs_size = instances.iter().fold(0, |acc, x| usize::max(acc, x.len()));

        let instances: Vec<&[E::Scalar]> = instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let params_verifier: ParamsVerifier<E> = params.verifier(inputs_size).unwrap();
        let strategy = SingleVerifier::new(&params_verifier);

        #[cfg(feature = "perf")]
        let advices = {
            use halo2_proofs::plonk::generate_advice_from_synthesize;
            use std::sync::Arc;
            use zkwasm_prover::prepare_advice_buffer;

            let mut advices = Arc::new(prepare_advice_buffer(pkey, false));

            generate_advice_from_synthesize(
                &params,
                pkey,
                c,
                &instances,
                &unsafe { Arc::get_mut_unchecked(&mut advices) }
                    .iter_mut()
                    .map(|x| (&mut x[..]) as *mut [_])
                    .collect::<Vec<_>>()[..],
            );

            advices
        };

        #[cfg(feature = "perf")]
        macro_rules! perf_gen_proof {
            ($transcript: expr, $schema: expr) => {{
                use zkwasm_prover::create_proof_from_advices_with_gwc;
                use zkwasm_prover::create_proof_from_advices_with_shplonk;

                match $schema {
                    OpenSchema::GWC => create_proof_from_advices_with_gwc(
                        &params,
                        pkey,
                        &instances,
                        advices,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                    OpenSchema::Shplonk => create_proof_from_advices_with_shplonk(
                        &params,
                        pkey,
                        &instances,
                        advices,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                }
            }};
        }

        #[cfg(not(feature = "perf"))]
        macro_rules! halo2_gen_proof {
            ($transcript: expr, $schema: expr) => {
                use ark_std::rand::rngs::OsRng;
                use halo2_proofs::plonk::create_proof as create_proof_with_gwc;
                use halo2_proofs::plonk::create_proof_with_shplonk;
                match $schema {
                    OpenSchema::GWC => create_proof_with_gwc(
                        &params,
                        &pkey,
                        std::slice::from_ref(c),
                        [instances.as_slice()].as_slice(),
                        OsRng,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                    OpenSchema::Shplonk => create_proof_with_shplonk(
                        &params,
                        &pkey,
                        std::slice::from_ref(c),
                        [instances.as_slice()].as_slice(),
                        OsRng,
                        &mut $transcript,
                    )
                    .expect("proof generation should not fail"),
                }
            };
        }

        macro_rules! verify_proof {
            ($reader: expr, $schema: expr, $r: expr) => {
                match $schema {
                    OpenSchema::GWC => verify_proof(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut $reader,
                    )
                    .unwrap(),
                    OpenSchema::Shplonk => verify_proof_with_shplonk(
                        &params_verifier,
                        &pkey.get_vk(),
                        strategy,
                        &[&instances.iter().map(|x| &x[..]).collect::<Vec<_>>()[..]],
                        &mut $reader,
                    )
                    .unwrap(),
                }
                log::info!("verify halo2 proof succeed");
            };
        }

        let timer = start_timer!(|| "creating proof ...");
        let r = match hashtype {
            HashType::Poseidon => {
                let mut transcript = PoseidonWrite::init(vec![]);
                #[cfg(feature = "perf")]
                perf_gen_proof!(transcript, schema);
                #[cfg(not(feature = "perf"))]
                halo2_gen_proof!(transcript, schema);
                let r = transcript.finalize();
                let mut reader = PoseidonRead::init(&r[..]);
                verify_proof!(reader, schema, r);
                r
            }
            HashType::Sha => {
                let mut transcript = ShaWrite::<_, _, _, sha2::Sha256>::init(vec![]);
                #[cfg(feature = "perf")]
                perf_gen_proof!(transcript, schema);
                #[cfg(not(feature = "perf"))]
                halo2_gen_proof!(transcript, schema);
                let r = transcript.finalize();
                let mut reader = ShaRead::<_, _, _, sha2::Sha256>::init(&r[..]);
                verify_proof!(reader, schema, r);
                r
            }
            HashType::Keccak => {
                let mut transcript = ShaWrite::<_, _, _, sha3::Keccak256>::init(vec![]);
                #[cfg(feature = "perf")]
                perf_gen_proof!(transcript, schema);
                #[cfg(not(feature = "perf"))]
                halo2_gen_proof!(transcript, schema);
                let r = transcript.finalize();
                let mut reader = ShaRead::<_, _, _, sha3::Keccak256>::init(&r[..]);
                verify_proof!(reader, schema, r);
                r
            }
        };
        end_timer!(timer);
        r
    }
}
