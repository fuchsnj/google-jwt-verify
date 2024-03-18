use crate::algorithm::Algorithm;
use base64::DecodeError;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidToken,
    RetrieveKeyFailure,
    UnsupportedAlgorithm(Algorithm),
    Expired,
    #[cfg(feature = "rust-ssl")]
    Rsa(rsa::errors::Error),
}

impl From<DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::InvalidToken
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::InvalidToken
    }
}

#[cfg(feature = "native-ssl")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Error::InvalidToken
    }
}

#[cfg(feature = "rust-ssl")]
impl From<rsa::errors::Error> for Error {
    fn from(e: rsa::errors::Error) -> Self {
        Error::Rsa(e)
    }
}
