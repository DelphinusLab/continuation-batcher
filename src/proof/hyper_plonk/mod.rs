use crate::args::HashType;
use crate::args::OpenSchema;
use halo2_proofs::arithmetic::Engine;
use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::helpers::Serializable;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::commitment::ParamsVerifier;

use plonkish_backend::backend::hyperplonk;
use plonkish_backend::backend::hyperplonk::{HyperPlonkProverParam, HyperPlonkVerifierParam};

use serde::{de::DeserializeOwned, Serialize};
use std::fs::OpenOptions;
use std::hash::Hash;

use halo2aggregator_s::circuits::utils::ProveSchema;
use halo2aggregator_s::transcript::poseidon::PoseidonRead;
use halo2aggregator_s::transcript::poseidon::PoseidonWrite;
use plonkish_backend::backend::PlonkishBackend;
use plonkish_backend::pcs::multilinear::Zeromorph;
use plonkish_backend::pcs::univariate::UnivariateKzg;
use std::marker::PhantomData;
use std::path::Path;

use super::AnyProvingKey;
use super::ProverBackend;
use super::ProvingKeyCache;

#[derive(Clone, Debug)]
pub struct HyperPlonkBackend<E: std::fmt::Debug>(PhantomData<E>);

impl<E: MultiMillerLoop + std::fmt::Debug> ProverBackend<E> for HyperPlonkBackend<E>
where
    <E as Engine>::G1Affine: Serialize + DeserializeOwned,
    <E as Engine>::G2Affine: Serialize + DeserializeOwned,
    <E as Engine>::Scalar: Serialize + DeserializeOwned + Hash,
{
    type VerifierParam = HyperPlonkVerifierParam<E::G1Affine>;
    type ProverParam = HyperPlonkProverParam<E::G1Affine>;

    fn load_vkey<C: Circuit<E::Scalar>>(
        _params: &Params<E::G1Affine>,
        param_folder: &Path,
    ) -> Self::VerifierParam {
        log::info!("read vkey from {:?}", param_folder);
        let mut fd = std::fs::File::open(&param_folder).unwrap();
        Self::VerifierParam::fetch::<_>(&mut fd).unwrap()
    }

    fn load_or_build_pkey<'a, C: Circuit<E::Scalar>>(
        params: &Params<E::G1Affine>,
        circuit: &C,
        cache_file: &Path,
        vkey_file: &Path,
        pkey_cache: &'a mut ProvingKeyCache<E>,
    ) -> &'a HyperPlonkProverParam<E::G1Affine> {
        use ark_std::{end_timer, start_timer};
        let key = cache_file.to_str().unwrap().to_string();
        if pkey_cache.contains(&key) {
            log::info!("pkey find in cache. Key: {:?}", &key);
            pkey_cache.get(&key).as_hyperplonk().unwrap()
        } else {
            log::info!("pkey not found in cache. Key: {:?}", &key);
            let pkey = if Path::exists(&cache_file) {
                let timer = start_timer!(|| "test read hyper pk info full ...");
                let pkey = Self::read_pk_full(params, &cache_file);
                //assert_eq!(vkey.domain, pkey.get_vk().domain);
                //assert_eq!(vkey.fixed_commitments, pkey.get_vk().fixed_commitments);
                end_timer!(timer);
                pkey
            } else {
                let vkey = ProveSchema::UseHyperPlonk.load_or_build_vkey::<E, C>(
                    params,
                    circuit,
                    Some(vkey_file),
                );
                let pkey =
                    hyperplonk::keygen_pk::<E, C>(&params, vkey.as_hyper_plonk().unwrap(), circuit)
                        .expect("keygen_pk should not fail");
                let timer = start_timer!(|| "storing hyper pk info full ...");
                Self::store_pk_full(
                    params,
                    &pkey,
                    vkey.as_hyper_plonk().unwrap(),
                    circuit,
                    cache_file,
                );
                end_timer!(timer);
                pkey
            };

            pkey_cache
                .push(key, AnyProvingKey::HyperPlonk(pkey))
                .as_hyperplonk()
                .unwrap()
        }
    }

    fn store_pk_full<C: Circuit<E::Scalar>>(
        _params: &Params<E::G1Affine>,
        pkey: &Self::ProverParam,
        _vkey: &Self::VerifierParam,
        _circuit: &C,
        cache_file: &Path,
    ) {
        log::info!("store pkey full to {:?}", cache_file);
        let mut fd = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&cache_file)
            .unwrap();
        pkey.store(&mut fd).unwrap()
    }
    fn read_pk_full(_params: &Params<E::G1Affine>, cache_file: &Path) -> Self::ProverParam {
        use ark_std::{end_timer, start_timer};
        let timer = start_timer!(|| "fetch pkey full ...");
        let mut fd = std::fs::File::open(&cache_file).unwrap();
        let pk = HyperPlonkProverParam::fetch(&mut fd).unwrap();
        end_timer!(timer);
        pk
    }

    fn read_vkey_full(cache_file: &Path) -> Self::VerifierParam {
        log::info!("read vkey full from {:?}", cache_file);
        let mut fd = std::fs::File::open(&cache_file).unwrap();
        HyperPlonkVerifierParam::<E::G1Affine>::fetch(&mut fd).unwrap()
    }

    fn create_proof<C: Circuit<E::Scalar>>(
        c: &C,
        instances: &Vec<Vec<E::Scalar>>,
        params: &Params<E::G1Affine>,
        pkey: &Self::ProverParam,
        hashtype: HashType,
        _schema: OpenSchema,
    ) -> Vec<u8> {
        use ark_std::{end_timer, start_timer};

        let inputs_size = instances.iter().fold(0, |acc, x| usize::max(acc, x.len()));

        // let instances: Vec<[E::Scalar]> = instances.iter().map(|x| &x[..]).collect::<Vec<_>>();

        let params_verifier: ParamsVerifier<E> = params.verifier(inputs_size).unwrap();

        let hyper_circuit = plonkish_backend::transform::circuit::get_zkwasm_circuit::<E, C>(
            params.get_k(),
            &c,
            instances.clone(),
        );
        //TODO not copy, high cost
        let kzg_pk_params = plonkish_backend::pcs::univariate::UnivariateKzgProverParam::<E>::new(
            params.get_k() as usize,
            params.get_g(),
            params.get_g_lagrange().clone(),
            Some(params.g_cross.clone()),
        );
        let kzg_pk =
            plonkish_backend::pcs::multilinear::ZeromorphKzgProverParam::new(kzg_pk_params);
        let ps = plonkish_backend::backend::hyperplonk::HyperPlonkProverSetupParam { pcs: kzg_pk };

        let kzg_vk_params = plonkish_backend::pcs::univariate::UnivariateKzgVerifierParam::<E>::new(
            params_verifier.g1,
            params_verifier.g2,
            params_verifier.s_g2,
        );
        let kzg_vs =
            plonkish_backend::pcs::multilinear::ZeromorphKzgVerifierParam::new(kzg_vk_params);
        let vs = hyperplonk::HyperPlonkVerifierSetupParam { pcs: kzg_vs };

        let timer = start_timer!(|| "creating proof ...");
        let r = match hashtype {
            HashType::Poseidon => {
                let mut transcript = PoseidonWrite::init(vec![]);
                <hyperplonk::HyperPlonk<Zeromorph<UnivariateKzg<E>>> as PlonkishBackend<
                    E::G1Affine,
                >>::prove(&ps, &pkey, &hyper_circuit, &mut transcript)
                .expect("prove should not fail");
                let r = transcript.finalize();
                let mut reader = PoseidonRead::init(&r[..]);
                <hyperplonk::HyperPlonk<Zeromorph<UnivariateKzg<E>>> as PlonkishBackend<
                    E::G1Affine,
                >>::verify(&vs, pkey.get_vk(), instances, &mut reader)
                .unwrap();
                r
            }
            _ => {
                unimplemented!()
            }
        };
        end_timer!(timer);
        r
    }
}
