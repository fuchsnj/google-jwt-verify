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

pub type Client = GenericClient<GoogleSigninKeyProvider, GoogleSigninValidator>;

type ClientBuilder = GenericClientBuilder<GoogleSigninKeyProvider, GoogleSigninValidator>;

pub type FirebaseClient = GenericClient<FirebaseAuthenticationKeyProvider, FirebaseValidator>;

type FirebaseClientBuilder =
    GenericClientBuilder<FirebaseAuthenticationKeyProvider, FirebaseValidator>;

pub struct GenericClientBuilder<KP, V> {
    token_validator: V,
    key_provider: Arc<Mutex<KP>>,
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
}

impl FirebaseClientBuilder {
    pub fn new(project_id: &str) -> Self {
        let firebase_key_provider = FirebaseValidator::with_project_id(project_id);
        Self::custom(firebase_key_provider)
    }
}

impl<KP: Default, V> GenericClient<KP, V> {
    pub fn custom_builder(validator: V) -> GenericClientBuilder<KP, V> {
        GenericClientBuilder::<KP, V>::custom(validator)
    }
    pub fn custom(validator: V) -> GenericClient<KP, V> {
        Self::custom_builder(validator).build()
    }
}

impl<KP: Default, V> GenericClientBuilder<KP, V> {
    pub fn custom<TV>(token_validator: TV) -> GenericClientBuilder<KP, TV> {
        GenericClientBuilder {
            token_validator,
            key_provider: Arc::new(Mutex::new(KP::default())),
            check_expiration: true,
        }
    }
}

impl<KP, V> GenericClientBuilder<KP, V> {
    pub fn custom_key_provider<T>(self, provider: T) -> GenericClientBuilder<T, V> {
        GenericClientBuilder::<T, V> {
            token_validator: self.token_validator,
            key_provider: Arc::new(Mutex::new(provider)),
            check_expiration: self.check_expiration,
        }
    }
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
    key_provider: Arc<Mutex<T>>,
    check_expiration: bool,
}

impl FirebaseClient {
    pub fn new(project_id: &str) -> Self {
        Self::builder(project_id).build()
    }
    pub fn builder(
        project_id: &str,
    ) -> GenericClientBuilder<FirebaseAuthenticationKeyProvider, FirebaseValidator> {
        GenericClientBuilder::new(project_id)
    }
}

#[cfg(feature = "blocking")]
impl<KP: KeyProvider, V: Validator> GenericClient<KP, V> {
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
impl<KP: AsyncKeyProvider, V: Validator> GenericClient<KP, V> {
    pub async fn verify_token_with_payload_async<P>(
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

    pub async fn verify_token_async(
        &self,
        token_string: &str,
    ) -> Result<Token<(), V::RequiredClaims>, Error> {
        self.verify_token_with_payload_async::<()>(token_string)
            .await
    }

    pub async fn verify_id_token_async(
        &self,
        token_string: &str,
    ) -> Result<Token<V::IdPayload, V::RequiredClaims>, Error> {
        self.verify_token_with_payload_async(token_string).await
    }
}
