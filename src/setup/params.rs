use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::poly::commitment::Params;
use lru::LruCache;
use std::fs::File;
use std::io;
use std::num::NonZeroUsize;

use crate::names::name_of_params;

pub fn build_params<E: MultiMillerLoop>(k: u32) -> Params<E::G1Affine> {
    Params::<E::G1Affine>::unsafe_setup::<E>(k)
}

pub struct ParamsCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, Params<E::G1Affine>>,
}

impl<E: MultiMillerLoop> ParamsCache<E> {
    pub fn new(cache_size: usize) -> Self {
        let lrucache =
            LruCache::<String, Params<E::G1Affine>>::new(NonZeroUsize::new(cache_size).unwrap());
        ParamsCache { cache: lrucache }
    }

    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }

    pub fn insert<'a>(
        &'a mut self,
        key: String,
        v: Params<E::G1Affine>,
    ) -> Option<&'a Params<E::G1Affine>> {
        // self.cache.push(key.clone(), v)
        todo!()
    }

    pub fn get<'a>(&'a mut self, k: u32, key: &String) -> Option<&'a Params<E::G1Affine>> {
        todo!()
    }
}
