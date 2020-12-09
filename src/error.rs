use std::time::SystemTimeError;

use crate::algorithm::Algorithm;
use base64::DecodeError;

#[derive(Debug)]
pub enum Error<TCE: TokenClaimsError> {
    InvalidToken(TokenValidationError<TCE>),
    Verification(VerificationError),
    /// If unable to get the current system time
    CurrentTimestamp(SystemTimeError),
    RetrieveKeyFailure,
    /// Key with request ID doesn't exist, may have been rotated
    KeyDoesNotExist,
}

impl<TCE: TokenClaimsError + PartialEq> PartialEq for Error<TCE> {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Error::InvalidToken(tve1), Error::InvalidToken(tve2)) if tve1 == tve2)
            || matches!((self, other), (Error::Verification(ve1), Error::Verification(ve2)) if ve1 == ve2)
            || matches!((self, other), (Error::CurrentTimestamp(ste1), Error::CurrentTimestamp(ste2)) if ste1.duration() == ste2.duration())
            || matches!(
                (self, other),
                (Error::RetrieveKeyFailure, Error::RetrieveKeyFailure)
                    | (Error::KeyDoesNotExist, Error::KeyDoesNotExist)
            )
    }
}

impl<TCE: TokenClaimsError> From<VerificationError> for Error<TCE> {
    fn from(ve: VerificationError) -> Self {
        Self::Verification(ve)
    }
}

impl<TCE: TokenClaimsError> From<TokenValidationError<TCE>> for Error<TCE> {
    fn from(tve: TokenValidationError<TCE>) -> Self {
        Self::InvalidToken(tve)
    }
}

#[derive(Debug, PartialEq)]
pub enum TokenValidationError<TCE: TokenClaimsError> {
    /// Token should not be authorized by client given the claims
    Claims(TCE),
    /// If unable to get the serialized header
    Header(TokenSegmentError),
    /// If unable to get the serialized payload
    Payload(TokenSegmentError),
    /// If unable to get the serialized signature
    Signature(TokenSegmentError),
    /// If a serialized token segment does not match expected JSON schema
    Json(JsonDeserializationError),
}

impl<TCE: TokenClaimsError> From<TCE> for TokenValidationError<TCE> {
    fn from(tce: TCE) -> Self {
        Self::Claims(tce)
    }
}

pub trait TokenClaimsError {}

#[derive(Debug)]
pub enum JsonDeserializationError {
    Header(serde_json::Error),
    Claims(serde_json::Error),
    Payload(serde_json::Error),
}

impl PartialEq for JsonDeserializationError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other),
            (JsonDeserializationError::Header(e1), JsonDeserializationError::Header(e2)) |
            (JsonDeserializationError::Payload(e1), JsonDeserializationError::Payload(e2)) |
            (JsonDeserializationError::Claims(e1), JsonDeserializationError::Claims(e2)) if e1.to_string() == e2.to_string()
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum TokenSegmentError {
    Decoding(DecodeError),
    Absent,
}

impl<TCE: TokenClaimsError> From<SystemTimeError> for Error<TCE> {
    fn from(ste: SystemTimeError) -> Self {
        Self::CurrentTimestamp(ste)
    }
}

impl From<DecodeError> for TokenSegmentError {
    fn from(de: DecodeError) -> Self {
        Self::Decoding(de)
    }
}

#[derive(Debug)]
pub enum VerificationError {
    UnsupportedAlgorithm(Algorithm),
    Modulus(PublicComponentError),
    Exponent(PublicComponentError),
    Cryptography(openssl::error::ErrorStack),
}

impl PartialEq for VerificationError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (VerificationError::Modulus(pce1), VerificationError::Modulus(pce2)) |
            (VerificationError::Exponent(pce1), VerificationError::Exponent(pce2)) if pce1 == pce2)
            || matches!((self, other), (VerificationError::Cryptography(e1), VerificationError::Cryptography(e2)) if e1.to_string() == e2.to_string())
            || matches!((self, other), (VerificationError::UnsupportedAlgorithm(a1), VerificationError::UnsupportedAlgorithm(a2)) if a1 == a2)
    }
}

impl From<openssl::error::ErrorStack> for VerificationError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::Cryptography(e)
    }
}

#[derive(Debug)]
pub enum PublicComponentError {
    BigNumParse(openssl::error::ErrorStack),
    Decoding(DecodeError),
}

impl PartialEq for PublicComponentError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (PublicComponentError::Decoding(de1), PublicComponentError::Decoding(de2)) if de1 == de2)
            || matches!((self, other), (PublicComponentError::BigNumParse(e1), PublicComponentError::BigNumParse(e2)) if e1.to_string() == e2.to_string())
    }
}

impl From<openssl::error::ErrorStack> for PublicComponentError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::BigNumParse(e)
    }
}

impl From<DecodeError> for PublicComponentError {
    fn from(de: DecodeError) -> Self {
        Self::Decoding(de)
    }
}
