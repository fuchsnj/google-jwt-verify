#[cfg(test)]
mod test;

mod algorithm;
mod client;
mod error;
mod header;
mod jwk;
mod key_provider;
mod token;
mod unverified_token;

pub use crate::client::Client;
#[cfg(feature = "async")]
pub use crate::client::TokioClient;
pub use crate::token::{IdPayload, RequiredClaims, Token};
pub use error::Error;

fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(&input, base64::URL_SAFE)
}
