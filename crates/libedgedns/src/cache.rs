//! Shared cache for DNS responses
//!
//! The cache is currently shared across all threads, and maps
//! `CacheKey` keys to DNS responses in wire format.
//!
//! DNS responses are stored as originally received from upstream servers,
//! and need to be modified to fit the original format of client queries
//! before being actually sent to clients.
//!
//! The cache current uses the CLOCK-Pro algorithm, but can be trivially
//! replaced with the `arc-cache` or `cart-cache` crates that expose a
//! similar API (but might be subject to patents).
//!
//! With a typical workload, it is expected that the vast majority of cached
//! responses end up in the `frequent` section of the cache.
//! The `test` and `recent` section act as a security valve when a spike of
//! previously unknown queries is observed.

use crate::config::Config;
use crate::query_router::Scope;
use bytes::Bytes;
use clockpro_cache::*;
use coarsetime::{Duration, Instant};
use domain_core::bits::*;
use domain_core::iana::{Class, Rtype};
use parking_lot::Mutex;
use std::clone::Clone;
use std::fmt;
use std::ops::{Add, Sub};
use std::sync::Arc;
use std::u32;

/// Default TTL for empty responses
const CACHE_DEFAULT_TTL: u32 = 5;

/// A cache key is a normalized representation of [`Scope`], by default a DNS question.
/// Domain name order is determined according to the ‘canonical DNS
/// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1], and is case insensitive.
///
/// The cache key is classless, constructing it from any other class will panic.
///
/// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CacheKey {
    qname: Dname,
    qtype: Rtype,
    dnssec: bool,
    scope: Vec<u8>,
}

impl CacheKey {
    /// Set current scope for given cache key (an arbitrary byte slice).
    pub fn with_scope(mut self, scope: &[u8]) -> Self {
        self.scope.extend_from_slice(scope);
        self
    }
}

impl Default for CacheKey {
    fn default() -> Self {
        Self {
            qname: Dname::root(),
            qtype: Rtype::Null,
            dnssec: false,
            scope: Vec::new(),
        }
    }
}

impl From<(&Dname, Rtype, Class, bool)> for CacheKey {
    fn from((name, qtype, qclass, dnssec): (&Dname, Rtype, Class, bool)) -> Self {
        debug_assert_eq!(qclass, Class::In);
        Self {
            qname: name.clone(),
            qtype,
            dnssec,
            scope: Vec::new(),
        }
    }
}

impl From<&Message> for CacheKey {
    fn from(msg: &Message) -> Self {
        match msg.first_question() {
            Some(ref q) => Self {
                qname: q.qname().to_name(),
                qtype: q.qtype(),
                dnssec: match msg.opt() {
                    Some(opt) => opt.dnssec_ok(),
                    None => false
                },
                scope: Vec::new(),
            },
            None => Self::default(),
        }
    }
}

impl From<&Scope> for CacheKey {
    fn from(scope: &Scope) -> Self {
        let q = &scope.question;
        Self {
            qname: q.qname().to_name(),
            qtype: q.qtype(),
            dnssec: match scope.opt() {
                Some(opt) => opt.dnssec_ok(),
                None => false
            },
            scope: Vec::new(),
        }
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.qname.fmt(f)?;
        write!(f, " {:?}", self.qtype)?;
        if !self.scope.is_empty() {
            write!(f, "| {:?} ", self.scope)?;
        }
        Ok(())
    }
}

/// A cache entry is a DNS message that has an inception timestamp, and a TTL.
/// The TTL is always the smallest TTL from the message (or [`CACHE_DEFAULT_TTL`] if the message is empty).
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub inception: Instant,
    pub ttl: u32,
    pub packet: Message,
}

impl CacheEntry {
    /// Returns a reference to the underlying bytes value.
    pub fn as_bytes(&self) -> &Bytes {
        self.packet.as_bytes()
    }

    /// Returns a reference to the underlying DNS message.
    pub fn as_message(&self) -> Message {
        self.packet.clone()
    }

    /// Returns true if the cache entry is expired.
    pub fn is_expired(&self) -> bool {
        let now = Instant::recent();
        now > self.inception.add(Duration::from_secs(u64::from(self.ttl)))
    }

    /// Returns the amount of time elapsed since this entry was created.
    pub fn elapsed(&self) -> u32 {
        let now = Instant::recent();
        now.sub(self.inception).as_secs() as u32
    }
}

impl From<Message> for CacheEntry {
    fn from(item: Message) -> Self {
        // Calculate minimum TTL in message
        let mut records = 0;
        let mut ttl = u32::MAX;
        for (rr, _) in item.iter() {
            if let Ok(rr) = rr {
                records += 1;
                if rr.ttl() < ttl {
                    ttl = rr.ttl();
                }
            }
        }

        CacheEntry {
            inception: Instant::recent(),
            ttl: if records == 0 { CACHE_DEFAULT_TTL } else { ttl },
            packet: item,
        }
    }
}

#[derive(Clone)]
pub struct Cache {
    inner: Arc<Mutex<ClockProCache<CacheKey, CacheEntry>>>,
    min_ttl: u32,
    max_ttl: u32,
}

impl Cache {
    pub fn new(capacity: usize, min_ttl: u32, max_ttl: u32) -> Self {
        let inner = ClockProCache::new(capacity).expect("cache");
        Self {
            inner: Arc::new(Mutex::new(inner)),
            min_ttl,
            max_ttl,
        }
    }

    pub fn stats(&self) -> CacheStats {
        let cache = self.inner.lock();
        CacheStats {
            inserted: cache.inserted(),
            evicted: cache.evicted(),
            recent_len: cache.recent_len(),
            test_len: cache.test_len(),
            frequent_len: cache.frequent_len(),
        }
    }

    pub fn insert(&mut self, cache_key: CacheKey, mut entry: CacheEntry) -> bool {
        let mut cache = self.inner.lock();
        // Enforce configure TTL limits for cache
        entry.ttl = entry.ttl.min(self.max_ttl).max(self.min_ttl);
        cache.insert(cache_key, entry)
    }

    pub fn get(&mut self, cache_key: &CacheKey) -> Option<CacheEntry> {
        let mut cache = self.inner.lock();
        cache
            .get_mut(&cache_key)
            .and_then(|entry| {
                if !entry.is_expired() {
                    Some(entry.clone())
                } else {
                    None
                }
            })
            .or_else(|| {
                None
            })
    }
}

/// Build from configuration pattern
impl From<&Arc<Config>> for Cache {
    fn from(config: &Arc<Config>) -> Self {
        Self::new(config.cache_size, config.min_ttl, config.max_ttl)
    }
}

#[derive(Clone, Debug)]
pub struct CacheStats {
    pub inserted: u64,
    pub evicted: u64,
    pub recent_len: usize,
    pub test_len: usize,
    pub frequent_len: usize,
}

#[cfg(test)]
mod test {
    use super::{Cache, CacheKey};
    use crate::test_utils::{DOMAINS, MSG};
    use domain_core::iana::{Class, Rtype};
    use rand::distributions::{Distribution, Normal};
    use test::{black_box, Bencher};

    #[bench]
    fn insert_normal_1k(b: &mut Bencher) {
        let keys: Vec<_> = DOMAINS
            .iter()
            .map(|dname| CacheKey::from((dname, Rtype::A, Class::In, false)))
            .collect();
        let key_count = keys.len();
        let mut c = Cache::new(key_count / 100, 0, 3_600);

        // This should roughly cover all elements (within 3-sigma)
        let domains_half = (key_count / 2) as f64;
        let mut rng = rand::thread_rng();
        let normal = Normal::new(domains_half, domains_half / 3.0);
        let mut rand_iter = normal
            .sample_iter(&mut rng)
            .map(|x| (x as usize) % key_count);
        let mut bench_closure = || {
            for _ in 1..1000 {
                let i = rand_iter.next().unwrap();
                black_box(c.insert(keys[i].clone(), MSG.clone().into()));
            }
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }

    #[bench]
    fn get_normal_1k(b: &mut Bencher) {
        let keys: Vec<_> = DOMAINS
            .iter()
            .map(|dname| CacheKey::from((dname, Rtype::A, Class::In, false)))
            .collect();
        let key_count = keys.len();

        // The cache size is ~ 1x sigma (stddev) to retain roughly >68% of records
        let mut c = Cache::new(key_count / 3, 0, 3_600);

        // This should roughly cover all elements (within 3-sigma)
        let domains_half = (key_count / 2) as f64;
        let mut rng = rand::thread_rng();
        let normal = Normal::new(domains_half, domains_half / 3.0);
        let mut rand_iter = normal
            .sample_iter(&mut rng)
            .map(|x| (x as usize) % key_count);
        for _ in 1..key_count {
            let i = rand_iter.next().unwrap();
            black_box(c.insert(keys[i].clone(), MSG.clone().into()));
        }

        let mut bench_closure = || {
            for _ in 1..1000 {
                let i = rand_iter.next().unwrap();
                black_box(c.get(&keys[i]));
            }
        };

        // Warmup and test
        bench_closure();
        b.iter(bench_closure);
    }
}
