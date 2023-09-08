use std::collections::BTreeMap;
use halo2_proofs::arithmetic::Engine;
use crate::proof::PkeyT;

pub struct ProvingKeyCache<E: Engine>{
    pub cache: BTreeMap<String, PkeyT<E>>,
}

impl<E> ProvingKeyCache<E>
where
    E: Engine,
{
    pub fn new() -> Self {
        ProvingKeyCache {
            cache: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: PkeyT<E>) {
        self.cache.insert(key, value);
    }

    pub fn get(&self, key: String) -> Option<&PkeyT<E>> {
        self.cache.get(&key)
    }

    pub fn remove(&mut self, key: String) {
        self.cache.remove(&key);
    }
}

//------------------------------------------------------------------------------
/*
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use crate::proof::PkeyT;

const DEFAULT_CACHE_SIZE: usize = 5;


lazy_static::lazy_static! {
    pub static ref PK_MEM_CACHE: Mutex<LruCache<String, Option<PkeyT<E>>>> =
        Mutex::new(LruCache::<String, Option<PkeyT<E>>>::new(
            NonZeroUsize::new(DEFAULT_CACHE_SIZE).unwrap(),
        ));
}
*/

