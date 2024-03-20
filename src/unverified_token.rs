use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;

#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::KeyProvider;
use crate::{base64_decode, header::Header, jwk::JsonWebKey, Error, RequiredClaims, Token};

pub struct UnverifiedToken<P> {
    header: Header,
    signed_body: String,
    signature: Vec<u8>,
    claims: RequiredClaims,
    json_payload: P,
}

impl<P> UnverifiedToken<P>
where
    for<'a> P: Deserialize<'a>,
{
    pub fn validate(
        token_string: &str,
        check_expiration: bool,
        client_id: &str,
    ) -> Result<Self, Error> {
        let mut segments = token_string.split('.');
        let encoded_header = segments.next().ok_or(Error::InvalidToken(
            "missing segment: encoded header".to_owned(),
        ))?;
        let encoded_payload = segments.next().ok_or(Error::InvalidToken(
            "missing segment: encoded payload".to_owned(),
        ))?;
        let encoded_signature = segments.next().ok_or(Error::InvalidToken(
            "missing segment: encoded ignature".to_owned(),
        ))?;

        let decoded = base64_decode(encoded_header)?;
        let header: Header = serde_json::from_slice(&decoded).unwrap_or_else(|_| {
            panic!(
                "decoded header from {}",
                String::from_utf8(decoded).unwrap()
            )
        });
        let signed_body = format!("{}.{}", encoded_header, encoded_payload);
        let signature = base64_decode(encoded_signature)?;
        let payload = base64_decode(encoded_payload)?;
        let claims: RequiredClaims = serde_json::from_slice(&payload).unwrap_or_else(|_| {
            panic!(
                "decoded payload from {}",
                String::from_utf8(payload.clone()).unwrap()
            )
        });
        if claims.get_audience() != client_id {
            return Err(Error::InvalidToken(format!(
                "expected audience to inclue {client_id}, got {}",
                claims.get_audience()
            )));
        }
        let issuer = claims.get_issuer();
        if issuer != "https://accounts.google.com" && issuer != "accounts.google.com" {
            return Err(Error::InvalidToken(format!(
                "expected issuer (https://)?accounts.google.com, got {}",
                issuer
            )));
        }
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if check_expiration && claims.get_expires_at() < current_timestamp {
            return Err(Error::Expired);
        }
        if claims.get_issued_at() > claims.get_expires_at() {
            return Err(Error::InvalidToken(format!(
                "claims issued at is great than expires: {} > {}",
                claims.get_issued_at(),
                claims.get_expires_at()
            )));
        }
        let json_payload: P = serde_json::from_slice(&payload).unwrap_or_else(|_| {
            panic!(
                "expected payload from {}",
                String::from_utf8(payload).unwrap()
            )
        });
        Ok(Self {
            claims,
            signature,
            signed_body,
            json_payload,
            header,
        })
    }
}

impl<P> UnverifiedToken<P> {
    #[cfg(feature = "blocking")]
    pub fn verify<KP: KeyProvider>(self, key_provider: &Arc<Mutex<KP>>) -> Result<Token<P>, Error> {
        let key_id = self.header.key_id.clone();
        self.verify_with_key(key_provider.lock().unwrap().get_key(&key_id))
    }
    #[cfg(feature = "async")]
    pub async fn verify_async<KP: AsyncKeyProvider>(
        self,
        key_provider: &Arc<Mutex<KP>>,
    ) -> Result<Token<P>, Error> {
        let key_id = self.header.key_id.clone();
        self.verify_with_key(key_provider.lock().unwrap().get_key_async(&key_id).await)
    }
    fn verify_with_key(self, key: Result<Option<JsonWebKey>, ()>) -> Result<Token<P>, Error> {
        let key = match key {
            Ok(Some(key)) => key,
            Ok(None) => {
                return Err(Error::InvalidToken(
                    "key not present for verification".to_owned(),
                ))
            }
            Err(_) => return Err(Error::RetrieveKeyFailure),
        };
        key.verify(self.signed_body.as_bytes(), &self.signature)?;
        Ok(Token::new(self.claims, self.json_payload))
    }
}
