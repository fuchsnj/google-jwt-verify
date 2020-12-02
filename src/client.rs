use crate::base64_decode;
use crate::error::Error;
use crate::key_provider::{AsyncKeyProvider, GoogleKeyProvider, KeyProvider};
use crate::token::IdPayload;
use crate::token::RequiredClaims;
use crate::token::Token;
use serde::Deserialize;
use serde_derive::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub struct ClientBuilder {
    client_id: String,
    key_provider: Arc<Mutex<dyn KeyProvider + Send>>,
    check_expiration: bool,
}

pub struct AsyncClientBuilder {
    client_id: String,
    key_provider: Arc<Mutex<dyn AsyncKeyProvider + Send>>,
    check_expiration: bool,
}

impl AsyncClientBuilder {
    pub fn new(client_id: &str) -> AsyncClientBuilder {
        AsyncClientBuilder {
            client_id: client_id.to_owned(),
            key_provider: Arc::new(Mutex::new(GoogleKeyProvider::new())),
            check_expiration: true,
        }
    }
    pub fn custom_key_provider<T: AsyncKeyProvider + Send + 'static>(
        mut self,
        provider: T,
    ) -> Self {
        self.key_provider = Arc::new(Mutex::new(provider));
        self
    }

    pub fn unsafe_ignore_expiration(mut self) -> Self {
        self.check_expiration = false;
        self
    }

    pub fn build(self) -> AsyncClient {
        AsyncClient {
            client_id: self.client_id,
            key_provider: self.key_provider,
            check_expiration: self.check_expiration,
        }
    }
}

impl ClientBuilder {
    pub fn new(client_id: &str) -> ClientBuilder {
        ClientBuilder {
            client_id: client_id.to_owned(),
            key_provider: Arc::new(Mutex::new(GoogleKeyProvider::new())),
            check_expiration: true,
        }
    }
    pub fn custom_key_provider<T: KeyProvider + Send + 'static>(mut self, provider: T) -> Self {
        self.key_provider = Arc::new(Mutex::new(provider));
        self
    }

    pub fn unsafe_ignore_expiration(mut self) -> Self {
        self.check_expiration = false;
        self
    }

    pub fn build(self) -> Client {
        Client {
            client_id: self.client_id,
            key_provider: self.key_provider,
            check_expiration: self.check_expiration,
        }
    }
}

pub struct AsyncClient {
    client_id: String,
    key_provider: Arc<Mutex<dyn AsyncKeyProvider + Send>>,
    check_expiration: bool,
}

impl AsyncClient {
    pub fn builder(client_id: &str) -> AsyncClientBuilder {
        AsyncClientBuilder::new(client_id)
    }

    pub fn new(client_id: &str) -> AsyncClient {
        AsyncClientBuilder::new(client_id).build()
    }

    pub async fn verify_token_with_payload<P>(&self, token_string: &str) -> Result<Token<P>, Error>
    where
        for<'a> P: Deserialize<'a>,
    {
        let mut segments = token_string.split('.');
        let encoded_header = segments.next().ok_or(Error::InvalidToken)?;
        let encoded_payload = segments.next().ok_or(Error::InvalidToken)?;
        let encoded_signature = segments.next().ok_or(Error::InvalidToken)?;

        let header: Header = serde_json::from_slice(&base64_decode(&encoded_header)?)?;

        let key = match self
            .key_provider
            .lock()
            .unwrap()
            .get_key_async(&header.key_id)
            .await
        {
            Ok(Some(key)) => key,
            Ok(None) => return Err(Error::InvalidToken),
            Err(_) => return Err(Error::RetrieveKeyFailure),
        };
        let signed_body = format!("{}.{}", encoded_header, encoded_payload);
        let signature = base64_decode(&encoded_signature)?;
        key.verify(signed_body.as_bytes(), &signature)?;
        let payload = base64_decode(&encoded_payload)?;
        let claims: RequiredClaims = serde_json::from_slice(&payload)?;

        if claims.get_audience() != self.client_id {
            return Err(Error::InvalidToken);
        }
        let issuer = claims.get_issuer();
        if issuer != "https://accounts.google.com" && issuer != "accounts.google.com" {
            return Err(Error::InvalidToken);
        }
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if self.check_expiration {
            if claims.get_expires_at() < current_timestamp {
                return Err(Error::Expired);
            }
        }
        if claims.get_issued_at() > claims.get_expires_at() {
            return Err(Error::InvalidToken);
        }
        let decoded_payload: P = serde_json::from_slice(&payload)?;
        Ok(Token::new(claims, decoded_payload))
    }

    pub async fn verify_token(&self, token_string: &str) -> Result<Token<()>, Error> {
        self.verify_token_with_payload::<()>(token_string).await
    }

    pub async fn verify_id_token(&self, token_string: &str) -> Result<Token<IdPayload>, Error> {
        self.verify_token_with_payload(token_string).await
    }
}

pub struct Client {
    client_id: String,
    key_provider: Arc<Mutex<dyn KeyProvider + Send>>,
    check_expiration: bool,
}

impl Client {
    pub fn builder(client_id: &str) -> ClientBuilder {
        ClientBuilder::new(client_id)
    }

    pub fn new(client_id: &str) -> Client {
        ClientBuilder::new(client_id).build()
    }

    pub fn verify_token_with_payload<P>(&self, token_string: &str) -> Result<Token<P>, Error>
    where
        for<'a> P: Deserialize<'a>,
    {
        let mut segments = token_string.split('.');
        let encoded_header = segments.next().ok_or(Error::InvalidToken)?;
        let encoded_payload = segments.next().ok_or(Error::InvalidToken)?;
        let encoded_signature = segments.next().ok_or(Error::InvalidToken)?;

        let header: Header = serde_json::from_slice(&base64_decode(&encoded_header)?)?;

        let key = match self.key_provider.lock().unwrap().get_key(&header.key_id) {
            Ok(Some(key)) => key,
            Ok(None) => return Err(Error::InvalidToken),
            Err(_) => return Err(Error::RetrieveKeyFailure),
        };
        let signed_body = format!("{}.{}", encoded_header, encoded_payload);
        let signature = base64_decode(&encoded_signature)?;
        key.verify(signed_body.as_bytes(), &signature)?;
        let payload = base64_decode(&encoded_payload)?;
        let claims: RequiredClaims = serde_json::from_slice(&payload)?;

        if claims.get_audience() != self.client_id {
            return Err(Error::InvalidToken);
        }
        let issuer = claims.get_issuer();
        if issuer != "https://accounts.google.com" && issuer != "accounts.google.com" {
            return Err(Error::InvalidToken);
        }
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if self.check_expiration && claims.get_expires_at() < current_timestamp {
            return Err(Error::Expired);
        }
        if claims.get_issued_at() > claims.get_expires_at() {
            return Err(Error::InvalidToken);
        }
        let decoded_payload: P = serde_json::from_slice(&payload)?;
        Ok(Token::new(claims, decoded_payload))
    }

    pub fn verify_token(&self, token_string: &str) -> Result<Token<()>, Error> {
        self.verify_token_with_payload::<()>(token_string)
    }

    pub fn verify_id_token(&self, token_string: &str) -> Result<Token<IdPayload>, Error> {
        self.verify_token_with_payload(token_string)
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct Header {
    #[serde(rename = "kid")]
    key_id: String,
}
