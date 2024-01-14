use std::num::NonZeroUsize;

use halo2_proofs::arithmetic::MultiMillerLoop;
use halo2_proofs::plonk::ProvingKey;
use lru::LruCache;

pub struct ProvingKeyCache<E: MultiMillerLoop> {
    pub cache: LruCache<String, ProvingKey<E::G1Affine>>,
}

impl<E: MultiMillerLoop> ProvingKeyCache<E> {
    pub fn new(cache_size: usize) -> Self {
        let lrucache = LruCache::<String, ProvingKey<E::G1Affine>>::new(
            NonZeroUsize::new(cache_size).unwrap(),
        );
        ProvingKeyCache { cache: lrucache }
    }

    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }

    pub fn push<'a>(
        &'a mut self,
        key: String,
        v: ProvingKey<E::G1Affine>,
    ) -> &'a ProvingKey<E::G1Affine> {
        self.cache.push(key.clone(), v);
        self.cache.get(&key).unwrap()
    }
}
