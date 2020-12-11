use std::{error::Error as StdError, fmt::Debug, time::SystemTimeError};

use crate::algorithm::Algorithm;
use base64::DecodeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error<TCE: TokenClaimsError> {
    #[error(transparent)]
    InvalidToken(#[from] TokenValidationError<TCE>),
    #[error("problem verifying JWT signature using provided JWK with kid={kid}: {source}")]
    Verification {
        source: VerificationError,
        kid: String,
    },
    #[error("failed to determine the current timestamp {0}")]
    CurrentTimestamp(#[from] SystemTimeError),
    #[error("problem with getting public key of token's signature")]
    RetrieveKeyFailure,
    #[error(
        "key provider did not provide any JSON Web Keys with the same Key ID as the token's header"
    )]
    KeyDoesNotExist,
}

impl<TCE: TokenClaimsError + PartialEq> PartialEq for Error<TCE> {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Error::InvalidToken(tve1), Error::InvalidToken(tve2)) if tve1 == tve2)
            || matches!((self, other), (Error::Verification{source: ve1, kid: kid1}, Error::Verification{source: ve2, kid: kid2}) if ve1 == ve2 && kid1 == kid2)
            || matches!((self, other), (Error::CurrentTimestamp(ste1), Error::CurrentTimestamp(ste2)) if ste1.duration() == ste2.duration())
            || matches!(
                (self, other),
                (Error::RetrieveKeyFailure, Error::RetrieveKeyFailure)
                    | (Error::KeyDoesNotExist, Error::KeyDoesNotExist)
            )
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum TokenValidationError<TCE: TokenClaimsError> {
    #[error(transparent)]
    Claims(#[from] TCE),
    #[error("JWT header: {0}")]
    Header(TokenSegmentError),
    #[error("JWT payload: {0}")]
    Payload(TokenSegmentError),
    #[error("JWT signature: {0}")]
    Signature(TokenSegmentError),
    #[error(transparent)]
    Json(#[from] JsonDeserializationError),
}

pub trait TokenClaimsError: Debug + StdError + 'static {}

#[derive(Debug, Error)]
pub enum JsonDeserializationError {
    #[error("JWT header: {0}")]
    Header(serde_json::Error),
    #[error("JWT claims: {0}")]
    Claims(serde_json::Error),
    #[error("JWT payload: {0}")]
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

#[derive(Debug, Error, PartialEq)]
pub enum TokenSegmentError {
    #[error(transparent)]
    Decoding(#[from] DecodeError),
    #[error("segment is not present")]
    Absent,
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("the algorithm, {found:?}, is not supported. Only {expected:?} is supported")]
    UnsupportedAlgorithm {
        found: Algorithm,
        expected: Algorithm,
    },
    #[error("problem reading RSA modulus, n = {n}: {source}")]
    Modulus {
        source: PublicComponentError,
        n: String,
    },
    #[error("problem reading RSA public exponent, e = {e}: {source}")]
    Exponent {
        source: PublicComponentError,
        e: String,
    },
    #[error(transparent)]
    Cryptography(#[from] openssl::error::ErrorStack),
}

impl PartialEq for VerificationError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (VerificationError::Modulus{source: pce1, n: c1}, VerificationError::Modulus{source: pce2, n: c2}) |
            (VerificationError::Exponent{source: pce1, e: c1}, VerificationError::Exponent{source: pce2, e: c2}) if pce1 == pce2 && c1 == c2)
            || matches!((self, other), (VerificationError::Cryptography(e1), VerificationError::Cryptography(e2)) if e1.to_string() == e2.to_string())
            || matches!((self, other), (VerificationError::UnsupportedAlgorithm{found: a1, expected: e1}, VerificationError::UnsupportedAlgorithm{found: a2, expected: e2}) if a1 == a2 && e1 == e2)
    }
}

#[derive(Debug, Error)]
pub enum PublicComponentError {
    #[error(transparent)]
    BigNumParse(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Decoding(#[from] DecodeError),
}

impl PartialEq for PublicComponentError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (PublicComponentError::Decoding(de1), PublicComponentError::Decoding(de2)) if de1 == de2)
            || matches!((self, other), (PublicComponentError::BigNumParse(e1), PublicComponentError::BigNumParse(e2)) if e1.to_string() == e2.to_string())
    }
}
