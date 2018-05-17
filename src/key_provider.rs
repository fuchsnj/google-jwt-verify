use jwk::JsonWebKeySet;
use reqwest;
use serde_json;
use reqwest::header::{CacheControl, CacheDirective};
use std::time::{Instant, Duration};
use jwk::JsonWebKey;

const GOOGLE_CERT_URL: &'static str = "https://www.googleapis.com/oauth2/v3/certs";

pub trait KeyProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()>;
}

pub struct GoogleKeyProvider {
    cached: Option<JsonWebKeySet>,
    expiration_time: Instant,
}

impl GoogleKeyProvider {
    pub fn new() -> GoogleKeyProvider {
        GoogleKeyProvider {
            cached: None,
            expiration_time: Instant::now(),
        }
    }
    pub fn download_keys(&mut self) -> Result<&JsonWebKeySet, ()> {
        let mut result = reqwest::get(GOOGLE_CERT_URL).map_err(|_| ())?;
        let text = result.text().map_err(|_| ())?;
        let mut expiration_time = None;
        if let Some(cache_header) = result.headers().get::<CacheControl>() {
            cache_header.iter().for_each(|directive| {
                if let CacheDirective::MaxAge(age_seconds) = directive {
                    expiration_time = Some(Instant::now() + Duration::from_secs(*age_seconds as u64))
                }
            });
        }
        let key_set = serde_json::from_str(&text).map_err(|_| ())?;
        if let Some(expiration_time) = expiration_time {
            self.cached = Some(key_set);
            self.expiration_time = expiration_time;
        }
        Ok(self.cached.as_ref().unwrap())
    }
}

impl KeyProvider for GoogleKeyProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        if let Some(ref cached_keys) = self.cached {
            if self.expiration_time > Instant::now() {
                return Ok(cached_keys.get_key(key_id));
            }
        }
        Ok(self.download_keys()?.get_key(key_id))
    }
}

#[test]
pub fn test_google_provider() {
    let mut provider = GoogleKeyProvider::new();
    assert!(provider.get_key("test").is_ok());
    assert!(provider.get_key("test").is_ok());
}