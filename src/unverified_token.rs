#[cfg(feature = "blocking")]
use std::sync::Mutex;
use std::{fmt::Debug, sync::Arc};

use serde::Deserialize;

#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::KeyProvider;
use crate::{base64_decode, header::Header, jwk::JsonWebKey, validator::Validator, Error, Token};
use crate::{
    error::TokenSegmentError,
    error::{JsonDeserializationError, TokenValidationError},
};

#[derive(Debug)]
pub struct UnverifiedToken<P, C> {
    header: Header,
    signed_body: String,
    signature: Vec<u8>,
    claims: C,
    json_payload: P,
}

impl<P, C> UnverifiedToken<P, C>
where
    for<'a> P: Deserialize<'a>,
    for<'a> C: Deserialize<'a> + Clone + Debug,
{
    pub fn validate<V>(
        token_string: &str,
        validator: &V,
        current_timestamp: u64,
    ) -> Result<Self, TokenValidationError<V::ClaimsError>>
    where
        V: Validator<RequiredClaims = C>,
    {
        let mut segments = token_string.split('.');
        let encoded_header = segments
            .next()
            .ok_or(TokenValidationError::Header(TokenSegmentError::Absent))?;
        let encoded_payload = segments
            .next()
            .ok_or(TokenValidationError::Payload(TokenSegmentError::Absent))?;
        let encoded_signature = segments
            .next()
            .ok_or(TokenValidationError::Signature(TokenSegmentError::Absent))?;

        let header: Header = serde_json::from_slice(
            &base64_decode(&encoded_header).map_err(|e| TokenValidationError::Header(e.into()))?,
        )
        .map_err(|e| TokenValidationError::Json(JsonDeserializationError::Header(e)))?;
        let signed_body = format!("{}.{}", encoded_header, encoded_payload);
        let signature = base64_decode(&encoded_signature)
            .map_err(|e| TokenValidationError::Signature(e.into()))?;
        let payload =
            base64_decode(&encoded_payload).map_err(|e| TokenValidationError::Payload(e.into()))?;
        let claims: V::RequiredClaims = serde_json::from_slice(&payload)
            .map_err(|e| TokenValidationError::Json(JsonDeserializationError::Claims(e)))?;
        validator.validate_claims(&claims, current_timestamp)?;
        let json_payload: P = serde_json::from_slice(&payload)
            .map_err(|e| TokenValidationError::Json(JsonDeserializationError::Payload(e)))?;
        Ok(Self {
            claims,
            signature,
            signed_body,
            json_payload,
            header,
        })
    }
}

impl<P, C> UnverifiedToken<P, C>
where
    C: Clone + for<'a> Deserialize<'a> + Debug,
{
    #[cfg(feature = "blocking")]
    pub fn verify<KP: KeyProvider, V: Validator<RequiredClaims = C>>(
        self,
        key_provider: &Arc<Mutex<KP>>,
    ) -> Result<Token<P, C>, Error<V::ClaimsError>> {
        let key_id = self.header.key_id.clone();
        self.verify_with_key::<V>(key_provider.lock().unwrap().get_key(&key_id))
    }
    #[cfg(feature = "async")]
    pub async fn verify_async<KP: AsyncKeyProvider, V: Validator<RequiredClaims = C>>(
        self,
        key_provider: &Arc<tokio::sync::Mutex<KP>>,
    ) -> Result<Token<P, V::RequiredClaims>, Error<V::ClaimsError>> {
        let key_id = self.header.key_id.clone();
        self.verify_with_key::<V>(key_provider.lock().await.get_key_async(&key_id).await)
    }
    fn verify_with_key<V: Validator<RequiredClaims = C>>(
        self,
        key: Result<Option<JsonWebKey>, ()>,
    ) -> Result<Token<P, V::RequiredClaims>, Error<V::ClaimsError>> {
        let key = match key {
            Ok(Some(key)) => key,
            Ok(None) => return Err(Error::KeyDoesNotExist),
            Err(_) => return Err(Error::RetrieveKeyFailure),
        };
        key.verify(self.signed_body.as_bytes(), &self.signature)?;
        Ok(Token::new(self.claims, self.json_payload))
    }
}
