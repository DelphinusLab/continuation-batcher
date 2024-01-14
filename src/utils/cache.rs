use std::path::PathBuf;

use lru::LruCache;

// An Lru Cache Wrapper
pub struct Cache<V> {
    lru_cache: LruCache<PathBuf, V>,
}
