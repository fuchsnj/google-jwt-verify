use crate::algorithm::Algorithm;

#[derive(Debug, PartialEq)]
pub enum InvalidError {
    Base64(base64::DecodeError),
    Json(String),
    #[cfg(feature = "native-ssl")]
    OpenSSL(String),
    #[cfg(feature = "rust-ssl")]
    Crypto,
    TokenFormat(String),
    InvalidClaims(String),
    InvalidKeyId,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidToken(InvalidError),
    RetrieveKeyFailure,
    UnsupportedAlgorithm(Algorithm),
    Expired,
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::InvalidToken(InvalidError::Base64(e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::InvalidToken(InvalidError::Json(e.to_string()))
    }
}

#[cfg(feature = "native-ssl")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::InvalidToken(InvalidError::OpenSSL(e.to_string()))
    }
}

#[cfg(feature = "rust-ssl")]
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        // https://docs.rs/ring/0.17.8/ring/error/struct.Unspecified.html
        Error::InvalidToken(InvalidError::Crypto)
    }
}
