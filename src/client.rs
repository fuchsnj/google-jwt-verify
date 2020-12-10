#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::KeyProvider;
use crate::key_provider::{FirebaseValidator, GoogleSigninValidator};
use crate::time::current_timestamp;
use crate::token::Token;
use crate::unverified_token::UnverifiedToken;
use crate::{
    error::Error,
    key_provider::{FirebaseAuthenticationKeyProvider, GoogleSigninKeyProvider},
    validator::Validator,
};
use serde::Deserialize;

use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
};

pub type Client = GenericBlockingClient<GoogleSigninKeyProvider, GoogleSigninValidator>;

type GenericBlockingClient<KP, V> = GenericClient<Arc<Mutex<KP>>, V>;

type ClientBuilder = GenericBlockingClientBuilder<GoogleSigninKeyProvider, GoogleSigninValidator>;

type GenericBlockingClientBuilder<KP, V> = GenericClientBuilder<Arc<Mutex<KP>>, V>;

pub type FirebaseClient =
    GenericBlockingClient<FirebaseAuthenticationKeyProvider, FirebaseValidator>;

type FirebaseClientBuilder =
    GenericBlockingClientBuilder<FirebaseAuthenticationKeyProvider, FirebaseValidator>;

#[cfg(feature = "async")]
pub type GoogleSigninTokioClient =
    GenericTokioClient<GoogleSigninKeyProvider, GoogleSigninValidator>;

#[cfg(feature = "async")]
pub type FirebaseTokioClient =
    GenericTokioClient<FirebaseAuthenticationKeyProvider, FirebaseValidator>;

#[cfg(feature = "async")]
type GenericTokioClient<KP, V> = GenericClient<Arc<tokio::sync::Mutex<KP>>, V>;

#[cfg(feature = "async")]
type GenericTokioClientBuilder<KP, V> = GenericClientBuilder<Arc<tokio::sync::Mutex<KP>>, V>;

pub struct GenericClientBuilder<KP, V> {
    token_validator: V,
    key_provider: KP,
    mocked_timestamp: Option<u64>,
}

impl Client {
    pub fn builder(client_id: &str) -> ClientBuilder {
        let validator = GoogleSigninValidator::with_client_id(client_id);
        ClientBuilder::custom(validator)
    }
    pub fn new(client_id: &str) -> Self {
        Client::builder(client_id).build()
    }
    pub fn firebase_builder(project_id: &str) -> FirebaseClientBuilder {
        FirebaseClientBuilder::new(project_id)
    }
    pub fn google_signin_builder(client_id: &str) -> ClientBuilder {
        Self::builder(client_id)
    }
    pub fn new_firebase(project_id: &str) -> FirebaseClient {
        FirebaseClient::new(project_id)
    }
    pub fn new_google_signin(client_id: &str) -> Self {
        Self::new(client_id)
    }
}

impl FirebaseClientBuilder {
    pub fn new(project_id: &str) -> Self {
        let firebase_key_provider = FirebaseValidator::with_project_id(project_id);
        Self::custom(firebase_key_provider)
    }
}

impl<KP: Default, V> GenericBlockingClient<KP, V> {
    pub fn custom_builder(validator: V) -> GenericBlockingClientBuilder<KP, V> {
        GenericBlockingClientBuilder::<KP, V>::custom(validator)
    }
    pub fn custom(validator: V) -> Self {
        Self::custom_builder(validator).build()
    }
}

#[cfg(feature = "async")]
impl<KP: Default, V> GenericTokioClientBuilder<KP, V> {
    pub fn custom<TV>(token_validator: TV) -> GenericTokioClientBuilder<KP, TV> {
        GenericTokioClientBuilder {
            token_validator,
            key_provider: Arc::new(tokio::sync::Mutex::new(KP::default())),
            mocked_timestamp: None,
        }
    }
    pub fn custom_key_provider<T>(self, provider: T) -> GenericTokioClientBuilder<T, V> {
        GenericTokioClientBuilder {
            token_validator: self.token_validator,
            key_provider: Arc::new(tokio::sync::Mutex::new(provider)),
            mocked_timestamp: self.mocked_timestamp,
        }
    }
}

impl<KP: Default, V> GenericBlockingClientBuilder<KP, V> {
    pub fn custom<TV>(token_validator: TV) -> GenericBlockingClientBuilder<KP, TV> {
        GenericBlockingClientBuilder {
            token_validator,
            key_provider: Arc::new(Mutex::new(KP::default())),
            mocked_timestamp: None,
        }
    }
    pub fn custom_key_provider<T>(self, provider: T) -> GenericBlockingClientBuilder<T, V> {
        GenericBlockingClientBuilder {
            token_validator: self.token_validator,
            key_provider: Arc::new(Mutex::new(provider)),
            mocked_timestamp: self.mocked_timestamp,
        }
    }
    #[cfg(feature = "async")]
    pub fn tokio(self) -> GenericTokioClientBuilder<KP, V> {
        GenericTokioClientBuilder {
            token_validator: self.token_validator,
            key_provider: Arc::new(tokio::sync::Mutex::new(KP::default())),
            mocked_timestamp: self.mocked_timestamp,
        }
    }
}

impl<KP, V> GenericClientBuilder<KP, V> {
    pub fn unsafe_mock_timestamp(mut self, mocked_timestamp: u64) -> Self {
        self.mocked_timestamp = Some(mocked_timestamp);
        self
    }
    pub fn build(self) -> GenericClient<KP, V> {
        GenericClient {
            token_validator: self.token_validator,
            key_provider: self.key_provider,
            mocked_timestamp: self.mocked_timestamp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GenericClient<T, V> {
    token_validator: V,
    key_provider: T,
    mocked_timestamp: Option<u64>,
}

impl FirebaseClient {
    pub fn new(project_id: &str) -> Self {
        Self::builder(project_id).build()
    }
    pub fn builder(
        project_id: &str,
    ) -> GenericBlockingClientBuilder<FirebaseAuthenticationKeyProvider, FirebaseValidator> {
        GenericBlockingClientBuilder::new(project_id)
    }
}

#[cfg(feature = "blocking")]
impl<KP: KeyProvider, V: Validator> GenericBlockingClient<KP, V> {
    pub fn verify_token_with_payload<P>(&self, token_string: &str) -> VerifyTokenResult<V, P>
    where
        for<'a> P: Deserialize<'a> + Debug,
    {
        let unverified_token = UnverifiedToken::<P, _>::validate(
            token_string,
            &self.token_validator,
            self.mocked_timestamp.map_or_else(current_timestamp, Ok)?,
        )?;
        unverified_token.verify::<KP, V>(&self.key_provider)
    }

    pub fn verify_token(&self, token_string: &str) -> VerifyTokenResult<V, ()> {
        self.verify_token_with_payload::<()>(token_string)
    }

    pub fn verify_id_token(&self, token_string: &str) -> VerifyTokenResult<V, V::IdPayload> {
        self.verify_token_with_payload(token_string)
    }
}

type VerifyTokenResult<V, P> =
    Result<Token<P, <V as Validator>::RequiredClaims>, Error<<V as Validator>::ClaimsError>>;

#[cfg(feature = "async")]
impl<KP: AsyncKeyProvider, V: Validator> GenericTokioClient<KP, V> {
    pub async fn verify_token_with_payload<P>(&self, token_string: &str) -> VerifyTokenResult<V, P>
    where
        for<'a> P: Deserialize<'a> + Debug,
    {
        let unverified_token = UnverifiedToken::<P, V::RequiredClaims>::validate(
            token_string,
            &self.token_validator,
            self.mocked_timestamp.map_or_else(current_timestamp, Ok)?,
        )?;
        unverified_token
            .verify_async::<KP, V>(&self.key_provider)
            .await
    }

    pub async fn verify_token(&self, token_string: &str) -> VerifyTokenResult<V, ()> {
        self.verify_token_with_payload::<()>(token_string).await
    }

    pub async fn verify_id_token(&self, token_string: &str) -> VerifyTokenResult<V, V::IdPayload> {
        self.verify_token_with_payload(token_string).await
    }
}
