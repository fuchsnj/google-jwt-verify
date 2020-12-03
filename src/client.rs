use crate::error::Error;
#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
use crate::key_provider::GoogleKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::KeyProvider;
use crate::token::IdPayload;
use crate::token::Token;
use crate::unverified_token::UnverifiedToken;
use serde::Deserialize;

use std::sync::{Arc, Mutex};

pub type Client = GenericClient<GoogleKeyProvider>;

pub struct GenericClientBuilder<KP> {
    client_kind: Kind,
    key_provider: Arc<Mutex<KP>>,
    check_expiration: bool,
}

pub enum Kind {
    SignIn { client_id: String },
    Firebase { project_id: String },
}

impl Kind {
    pub fn valid_issuers(&self) -> Vec<String> {
        match self {
            Kind::SignIn { client_id: _ } => vec![
                "https://accounts.google.com".into(),
                "accounts.google.com".into(),
            ],
            Kind::Firebase { project_id } => {
                vec![format!("https://securetoken.google.com/{}", project_id)]
            }
        }
    }
    pub fn valid_audience(&self) -> &str {
        match self {
            Self::SignIn { client_id } => client_id,
            Self::Firebase { project_id } => project_id,
        }
    }
    pub fn certificate_url(&self) -> &'static str {
        match self {
            Kind::SignIn{client_id: _} => "https://www.googleapis.com/oauth2/v3/certs",
            Kind::Firebase{project_id: _} => "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
        }
    }
}

impl<KP: Default> GenericClientBuilder<KP> {
    pub fn new(client_id: &str) -> GenericClientBuilder<KP> {
        GenericClientBuilder::<KP> {
            client_kind: Kind::SignIn {
                client_id: client_id.to_owned(),
            },
            key_provider: Arc::new(Mutex::new(KP::default())),
            check_expiration: true,
        }
    }
}

impl GenericClientBuilder<GoogleKeyProvider> {
    pub fn firebase(project_id: &str) -> GenericClientBuilder<GoogleKeyProvider> {
        let client_kind = Kind::Firebase {
            project_id: project_id.to_owned(),
        };
        let firebase_key_provider =
            GoogleKeyProvider::with_certificate_url(client_kind.certificate_url());
        GenericClientBuilder {
            client_kind,
            key_provider: Arc::new(Mutex::new(firebase_key_provider)),
            check_expiration: true,
        }
    }
}

impl<KP> GenericClientBuilder<KP> {
    pub fn custom_key_provider<T>(self, provider: T) -> GenericClientBuilder<T> {
        GenericClientBuilder {
            client_kind: self.client_kind,
            key_provider: Arc::new(Mutex::new(provider)),
            check_expiration: self.check_expiration,
        }
    }
    pub fn unsafe_ignore_expiration(mut self) -> Self {
        self.check_expiration = false;
        self
    }
    pub fn build(self) -> GenericClient<KP> {
        GenericClient {
            client_kind: self.client_kind,
            key_provider: self.key_provider,
            check_expiration: self.check_expiration,
        }
    }
}

pub struct GenericClient<T> {
    client_kind: Kind,
    key_provider: Arc<Mutex<T>>,
    check_expiration: bool,
}

impl<KP: Default> GenericClient<KP> {
    pub fn builder(client_id: &str) -> GenericClientBuilder<KP> {
        GenericClientBuilder::<KP>::new(client_id)
    }
    pub fn new(client_id: &str) -> GenericClient<KP> {
        GenericClientBuilder::new(client_id).build()
    }
}

impl Client {
    pub fn firebase(project_id: &str) -> Self {
        GenericClientBuilder::firebase(project_id).build()
    }
    pub fn firebase_builder(project_id: &str) -> GenericClientBuilder<GoogleKeyProvider> {
        GenericClientBuilder::firebase(project_id)
    }
}

#[cfg(feature = "blocking")]
impl<KP: KeyProvider> GenericClient<KP> {
    pub fn verify_token_with_payload<P>(&self, token_string: &str) -> Result<Token<P>, Error>
    where
        for<'a> P: Deserialize<'a>,
    {
        let unverified_token =
            UnverifiedToken::<P>::validate(token_string, self.check_expiration, &self.client_kind)?;
        unverified_token.verify(&self.key_provider)
    }

    pub fn verify_token(&self, token_string: &str) -> Result<Token<()>, Error> {
        self.verify_token_with_payload::<()>(token_string)
    }

    pub fn verify_id_token(&self, token_string: &str) -> Result<Token<IdPayload>, Error> {
        self.verify_token_with_payload(token_string)
    }
}

#[cfg(feature = "async")]
impl<KP: AsyncKeyProvider> GenericClient<KP> {
    pub async fn verify_token_with_payload_async<P>(
        &self,
        token_string: &str,
    ) -> Result<Token<P>, Error>
    where
        for<'a> P: Deserialize<'a>,
    {
        let unverified_token =
            UnverifiedToken::<P>::validate(token_string, self.check_expiration, &self.client_kind)?;
        unverified_token.verify_async(&self.key_provider).await
    }

    pub async fn verify_token_async(&self, token_string: &str) -> Result<Token<()>, Error> {
        self.verify_token_with_payload_async::<()>(token_string)
            .await
    }

    pub async fn verify_id_token_async(
        &self,
        token_string: &str,
    ) -> Result<Token<IdPayload>, Error> {
        self.verify_token_with_payload_async(token_string).await
    }
}
