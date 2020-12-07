use crate::jwk::JsonWebKeySet;
use crate::{
    jwk::JsonWebKey,
    token::{
        FirebaseIdPayload, FirebaseRequiredClaims, GoogleSigninIdPayload,
        GoogleSigninRequiredClaims,
    },
    validator::Validator,
};
#[cfg(feature = "async")]
use async_trait::async_trait;
use headers::{Header, HeaderMap};
use reqwest::header::CACHE_CONTROL;
use std::time::Instant;

#[cfg(feature = "blocking")]
pub trait KeyProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()>;
}

#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncKeyProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()>;
}

#[derive(Default)]
pub struct GoogleSigninKeyProvider {
    cache: Option<(JsonWebKeySet, Instant)>,
}

pub struct GoogleSigninValidator {
    client_id: String,
}

impl GoogleSigninValidator {
    pub fn with_client_id(client_id: &str) -> Self {
        Self {
            client_id: client_id.into(),
        }
    }
}

impl GoogleKeyProvider for GoogleSigninKeyProvider {
    fn valid_cache(&self) -> Option<&JsonWebKeySet> {
        self.cache.as_ref().and_then(|(cache, expiration)| {
            if expiration > &Instant::now() {
                Some(cache)
            } else {
                None
            }
        })
    }
    fn update_cache(&mut self, key_set: JsonWebKeySet, expiration: Instant) {
        self.cache = Some((key_set, expiration));
    }
    fn certificate_url() -> &'static str {
        "https://www.googleapis.com/oauth2/v3/certs"
    }
}

impl Validator for GoogleSigninValidator {
    type RequiredClaims = GoogleSigninRequiredClaims;
    type IdPayload = GoogleSigninIdPayload;
    fn claims_are_valid(&self, claims: &Self::RequiredClaims) -> bool {
        claims.valid_for_client(&self.client_id)
    }
}

#[derive(Default)]
pub struct FirebaseAuthenticationKeyProvider {
    cache: Option<(JsonWebKeySet, Instant)>,
}

impl FirebaseValidator {
    pub fn with_project_id(project_id: &str) -> Self {
        Self {
            project_id: project_id.into(),
        }
    }
}

pub struct FirebaseValidator {
    project_id: String,
}

impl Validator for FirebaseValidator {
    type RequiredClaims = FirebaseRequiredClaims;
    type IdPayload = FirebaseIdPayload;
    fn claims_are_valid(&self, claims: &Self::RequiredClaims) -> bool {
        claims.valid_for_project(&self.project_id)
    }
}

impl GoogleKeyProvider for FirebaseAuthenticationKeyProvider {
    fn valid_cache(&self) -> Option<&JsonWebKeySet> {
        self.cache.as_ref().and_then(|(cache, expiration)| {
            if expiration > &Instant::now() {
                Some(cache)
            } else {
                None
            }
        })
    }
    fn update_cache(&mut self, key_set: JsonWebKeySet, expiration: Instant) {
        self.cache = Some((key_set, expiration));
    }
    fn certificate_url() -> &'static str {
        "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
    }
}

pub trait GoogleKeyProvider: Default {
    fn valid_cache(&self) -> Option<&JsonWebKeySet>;
    fn update_cache(&mut self, key_set: JsonWebKeySet, expiration: Instant);
    fn certificate_url() -> &'static str;
}

fn process_response<'a>(
    key_provider: &'a mut impl GoogleKeyProvider,
    headers: &HeaderMap,
    text: &str,
) -> Option<&'a JsonWebKeySet> {
    let x = headers.get_all(CACHE_CONTROL);
    if let (Ok(cache_header), Ok(key_set)) = (
        headers::CacheControl::decode(&mut x.iter()),
        serde_json::from_str(&text),
    ) {
        if let Some(max_age) = cache_header.max_age() {
            let expiration = Instant::now() + max_age;
            key_provider.update_cache(key_set, expiration);
        }
    }
    key_provider.valid_cache()
}

#[cfg(feature = "blocking")]
impl<T: GoogleKeyProvider> KeyProvider for T {
    fn get_key(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        if let Some(key_set) = self.valid_cache() {
            Ok(key_set.get_key(key_id))
        } else {
            let result = reqwest::blocking::get(T::certificate_url()).map_err(|_| ())?;
            Ok(process_response(
                self,
                &result.headers().clone(),
                &result.text().map_err(|_| ())?,
            )
            .and_then(|key_set| key_set.get_key(key_id)))
        }
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<T: GoogleKeyProvider + Send + Sync> AsyncKeyProvider for T {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        if let Some(key_set) = self.valid_cache() {
            Ok(key_set.get_key(key_id))
        } else {
            let url = T::certificate_url();
            if let Ok(response) = reqwest::get(url).await {
                let headers = response.headers().clone();
                if let Ok(text) = response.text().await {
                    Ok(process_response(self, &headers, &text)
                        .and_then(|key_set| key_set.get_key(key_id)))
                } else {
                    Err(())
                }
            } else {
                Err(())
            }
        }
    }
}

#[cfg(feature = "blocking")]
#[test]
pub fn test_google_provider() {
    let mut provider = GoogleSigninKeyProvider::default();
    assert!(provider.get_key("test").is_ok());
    assert!(provider.get_key("test").is_ok());

    let mut provider = FirebaseAuthenticationKeyProvider::default();
    assert!(provider.get_key("test").is_ok());
    assert!(provider.get_key("test").is_ok());
}

#[cfg(all(test, feature = "async"))]
mod async_test {
    use super::AsyncKeyProvider;
    use crate::key_provider::{FirebaseAuthenticationKeyProvider, GoogleSigninKeyProvider};
    use tokio;
    #[tokio::test]
    async fn test_google_provider_async() {
        let mut provider = GoogleSigninKeyProvider::default();
        assert!(provider.get_key_async("test").await.is_ok());
        assert!(provider.get_key_async("test").await.is_ok());

        let mut provider = FirebaseAuthenticationKeyProvider::default();
        assert!(provider.get_key_async("test").await.is_ok());
        assert!(provider.get_key_async("test").await.is_ok());
    }
}
