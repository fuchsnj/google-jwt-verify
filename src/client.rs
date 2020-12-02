use crate::{jwk::JsonWebKey, base64_decode};
use crate::error::Error;
use crate::key_provider::{AsyncKeyProvider, GoogleKeyProvider, KeyProvider};
use crate::token::IdPayload;
use crate::token::RequiredClaims;
use crate::token::Token;
use serde::Deserialize as DeserializeTrait;
use serde_derive::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub type Client = GenericClient<GoogleKeyProvider>;

pub struct GenericClientBuilder<KP> {
    client_id: String,
    key_provider: Arc<Mutex<KP>>,
    check_expiration: bool,
}

impl<KP: Default> GenericClientBuilder<KP> {
    pub fn new(client_id: &str) -> GenericClientBuilder<KP> {
        GenericClientBuilder::<KP> {
            client_id: client_id.to_owned(),
            key_provider: Arc::new(Mutex::new(KP::default())),
            check_expiration: true,
        }
    }
}

impl<KP> GenericClientBuilder<KP> {
    pub fn custom_key_provider<T>(self, provider: T) -> GenericClientBuilder<T> {
        GenericClientBuilder {
            client_id: self.client_id,
            key_provider: Arc::new(Mutex::new(provider)),
            check_expiration: self.check_expiration
        }
    }
    pub fn unsafe_ignore_expiration(mut self) -> Self {
        self.check_expiration = false;
        self
    }
    pub fn build(self) -> GenericClient<KP> {
        GenericClient {
            client_id: self.client_id,
            key_provider: self.key_provider,
            check_expiration: self.check_expiration,
        }
    }
}

pub struct GenericClient<T> {
    client_id: String,
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

impl<KP: KeyProvider> GenericClient<KP> {
    pub fn verify_token_with_payload<P>(&self, token_string: &str) -> Result<Token<P>, Error>
    where
        for<'a> P: DeserializeTrait<'a>,
    {
        let unverified_token = UnverifiedToken::<P>::validate(token_string, self.check_expiration, &self.client_id)?;
        unverified_token.verify(&self.key_provider)
    }

    pub fn verify_token(&self, token_string: &str) -> Result<Token<()>, Error> {
        self.verify_token_with_payload::<()>(token_string)
    }

    pub fn verify_id_token(&self, token_string: &str) -> Result<Token<IdPayload>, Error> {
        self.verify_token_with_payload(token_string)
    }
}

impl<KP: AsyncKeyProvider> GenericClient<KP> {
    pub async fn verify_token_with_payload_async<P>(&self, token_string: &str) -> Result<Token<P>, Error>
    where
        for<'a> P: DeserializeTrait<'a>,
    {
        let unverified_token = UnverifiedToken::<P>::validate(token_string, self.check_expiration, &self.client_id)?;
        unverified_token.verify_async(&self.key_provider).await
    }

    pub async fn verify_token_async(&self, token_string: &str) -> Result<Token<()>, Error> {
        self.verify_token_with_payload_async::<()>(token_string).await
    }

    pub async fn verify_id_token_async(&self, token_string: &str) -> Result<Token<IdPayload>, Error> {
        self.verify_token_with_payload_async(token_string).await
    }
}

struct UnverifiedToken<P> {
    header: Header,
    signed_body: String,
    signature: Vec<u8>,
    claims: RequiredClaims,
    json_payload: P
}

impl<P> UnverifiedToken<P>
where
    for<'a> P: DeserializeTrait<'a>
{
    fn validate(token_string: &str, check_expiration: bool, client_id: &str) -> Result<Self, Error> {
        let mut segments = token_string.split('.');
        let encoded_header = segments.next().ok_or(Error::InvalidToken)?;
        let encoded_payload = segments.next().ok_or(Error::InvalidToken)?;
        let encoded_signature = segments.next().ok_or(Error::InvalidToken)?;

        let header: Header = serde_json::from_slice(&base64_decode(&encoded_header)?)?;
        let signed_body = format!("{}.{}", encoded_header, encoded_payload);
        let signature = base64_decode(&encoded_signature)?;
        let payload = base64_decode(&encoded_payload)?;
        let claims: RequiredClaims = serde_json::from_slice(&payload)?;
        if claims.get_audience() != client_id {
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
        if check_expiration && claims.get_expires_at() < current_timestamp {
            return Err(Error::Expired);
        }
        if claims.get_issued_at() > claims.get_expires_at() {
            return Err(Error::InvalidToken);
        }
        let json_payload: P = serde_json::from_slice(&payload)?;
        Ok(Self {
            claims,
            signature,
            signed_body,
            json_payload,
            header
        })
    }
}

impl<P> UnverifiedToken<P> {
    pub fn verify<KP: KeyProvider>(self, key_provider: &Arc<Mutex<KP>>) -> Result<Token<P>, Error> {
        let key_id = self.header.key_id.clone();
        self.verify_with_key(key_provider.lock().unwrap().get_key(&key_id))
    }
    pub async fn verify_async<KP: AsyncKeyProvider>(self, key_provider: &Arc<Mutex<KP>>) ->  Result<Token<P>, Error> {
        let key_id = self.header.key_id.clone();
        self.verify_with_key(key_provider.lock().unwrap().get_key_async(&key_id).await)
    }
    fn verify_with_key(self, key: Result<Option<JsonWebKey>, ()>) -> Result<Token<P>, Error> {
        let key = match key {
            Ok(Some(key)) => key,
            Ok(None) => return Err(Error::InvalidToken),
            Err(_) => return Err(Error::RetrieveKeyFailure),
        };
        key.verify(self.signed_body.as_bytes(), &self.signature)?;
        Ok(Token::new(self.claims, self.json_payload))
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct Header {
    #[serde(rename = "kid")]
    key_id: String,
}
