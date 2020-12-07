#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::{FirebaseValidator, GoogleSigninValidator, KeyProvider};
use crate::token::Token;
use crate::unverified_token::UnverifiedToken;
use crate::{
    error::Error,
    key_provider::{FirebaseAuthenticationKeyProvider, GoogleSigninKeyProvider},
    validator::Validator,
};
use serde::Deserialize;

use std::sync::{Arc, Mutex};

pub type Client = GenericBlockingClient<GoogleSigninKeyProvider, GoogleSigninValidator>;

type GenericBlockingClient<KP, V> = GenericClient<Arc<Mutex<KP>>, V>;

type ClientBuilder = GenericBlockingClientBuilder<GoogleSigninKeyProvider, GoogleSigninValidator>;

type GenericBlockingClientBuilder<KP, V> = GenericClientBuilder<Arc<Mutex<KP>>, V>;

pub type FirebaseClient = GenericBlockingClient<FirebaseAuthenticationKeyProvider, FirebaseValidator>;

type FirebaseClientBuilder =
    GenericBlockingClientBuilder<FirebaseAuthenticationKeyProvider, FirebaseValidator>;

#[cfg(feature = "async")]
pub type GenericTokioClient<KP, V> = GenericClient<Arc<tokio::sync::Mutex<KP>>, V>;


#[cfg(feature = "async")]
type GenericTokioClientBuilder<KP, V> = GenericClientBuilder<Arc<tokio::sync::Mutex<KP>>, V>;

pub struct GenericClientBuilder<KP, V> {
    token_validator: V,
    key_provider: KP,
    check_expiration: bool,
}

impl Client {
    pub fn builder(client_id: &str) -> ClientBuilder {
        let validator = GoogleSigninValidator::with_client_id(client_id);
        ClientBuilder::custom(validator)
    }
    pub fn new(client_id: &str) -> Self {
        Client::builder(client_id).build()
    }
    pub fn firebase(project_id: &str) -> FirebaseClientBuilder {
        FirebaseClientBuilder::new(project_id)
    }
    pub fn google_signin(client_id: &str) -> ClientBuilder {
        Self::builder(client_id)
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
            check_expiration: true,
        }
    }
    pub fn custom_key_provider<T>(self, provider: T) -> GenericTokioClientBuilder<T, V> {
        GenericTokioClientBuilder {
            token_validator: self.token_validator,
            key_provider: Arc::new(tokio::sync::Mutex::new(provider)),
            check_expiration: self.check_expiration,
        }
    }
}

impl<KP: Default, V> GenericBlockingClientBuilder<KP, V> {
    pub fn custom<TV>(token_validator: TV) -> GenericBlockingClientBuilder<KP, TV> {
        GenericBlockingClientBuilder {
            token_validator,
            key_provider: Arc::new(Mutex::new(KP::default())),
            check_expiration: true,
        }
    }
    pub fn custom_key_provider<T>(self, provider: T) -> GenericBlockingClientBuilder<T, V> {
        GenericBlockingClientBuilder {
            token_validator: self.token_validator,
            key_provider: Arc::new(Mutex::new(provider)),
            check_expiration: self.check_expiration,
        }
    }
    #[cfg(feature = "async")]
    pub fn tokio(self) -> GenericTokioClientBuilder<KP, V> {
        GenericTokioClientBuilder {
            token_validator: self.token_validator,
            key_provider: Arc::new(tokio::sync::Mutex::new(KP::default())),
            check_expiration: self.check_expiration
        }
    }
}

impl<KP, V> GenericClientBuilder<KP, V> {
    pub fn unsafe_ignore_expiration(mut self) -> Self {
        self.check_expiration = false;
        self
    }
    pub fn build(self) -> GenericClient<KP, V> {
        GenericClient {
            token_validator: self.token_validator,
            key_provider: self.key_provider,
            check_expiration: self.check_expiration,
        }
    }
}

pub struct GenericClient<T, V> {
    token_validator: V,
    key_provider: T,
    check_expiration: bool,
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
    pub fn verify_token_with_payload<P>(
        &self,
        token_string: &str,
    ) -> Result<Token<P, V::RequiredClaims>, Error>
    where
        for<'a> P: Deserialize<'a>,
    {
        let unverified_token = UnverifiedToken::<P, _>::validate(
            token_string,
            self.check_expiration,
            &self.token_validator,
        )?;
        println!("validated token");
        unverified_token.verify(&self.key_provider)
    }

    pub fn verify_token(&self, token_string: &str) -> Result<Token<(), V::RequiredClaims>, Error> {
        self.verify_token_with_payload::<()>(token_string)
    }

    pub fn verify_id_token(
        &self,
        token_string: &str,
    ) -> Result<Token<V::IdPayload, V::RequiredClaims>, Error> {
        self.verify_token_with_payload(token_string)
    }
}

#[cfg(feature = "async")]
impl<KP: AsyncKeyProvider, V: Validator> GenericTokioClient<KP, V> {
    pub async fn verify_token_with_payload<P>(
        &self,
        token_string: &str,
    ) -> Result<Token<P, V::RequiredClaims>, Error>
    where
        for<'a> P: Deserialize<'a>,
    {
        let unverified_token = UnverifiedToken::<P, V::RequiredClaims>::validate(
            token_string,
            self.check_expiration,
            &self.token_validator,
        )?;
        unverified_token.verify_async(&self.key_provider).await
    }

    pub async fn verify_token(
        &self,
        token_string: &str,
    ) -> Result<Token<(), V::RequiredClaims>, Error> {
        self.verify_token_with_payload::<()>(token_string)
            .await
    }

    pub async fn verify_id_token(
        &self,
        token_string: &str,
    ) -> Result<Token<V::IdPayload, V::RequiredClaims>, Error> {
        self.verify_token_with_payload(token_string).await
    }
}
