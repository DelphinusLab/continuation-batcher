use halo2_proofs::arithmetic::Engine;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::plonk::ProvingKey;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

const DEFAULT_CACHE_SIZE: usize = 5;

pub struct PkeyParams<Y: Engine> {
    pub pkey: ProvingKey<<Y as Engine>::G1Affine>,
    pub params: Params<<Y as Engine>::G1Affine>,
}

impl<Y: Engine> PkeyParams<Y> {
    pub fn new(
        pkey: ProvingKey<<Y as Engine>::G1Affine>,
        params: Params<<Y as Engine>::G1Affine>,
    ) -> Self {
        PkeyParams {
            pkey,
            params,
        }
    }
}

pub struct ProvingKeyCache<Y: Engine> {
    pub pk_mem_cache: Mutex<LruCache::<String, PkeyParams<Y>>>,
}

impl <Y: Engine> ProvingKeyCache<Y> {
    pub fn new() -> Self {
        let cache = LruCache::<String, PkeyParams<Y>>::new(
            NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap()
        );
        ProvingKeyCache {
            pk_mem_cache: Mutex::new(cache)
        }
    }
}
