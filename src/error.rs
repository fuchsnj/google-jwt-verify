use crate::algorithm::Algorithm;
use base64::DecodeError;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidToken(String),
    RetrieveKeyFailure,
    UnsupportedAlgorithm(Algorithm),
    Expired,
}

impl From<DecodeError> for Error {
    fn from(_: DecodeError) -> Self {
        Error::InvalidToken("decode error".to_owned())
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::InvalidToken("serde json error".to_owned())
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Error::InvalidToken("openssl error stack".to_owned())
    }
}
