#[cfg(test)]
mod test;

mod key_provider;
mod algorithm;
mod error;
mod jwk;
mod client;
mod token;

pub use crate::client::Client;
pub use crate::token::{Token, IdPayload, RequiredClaims};
pub use error::Error;

fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(&input, base64::URL_SAFE)
}
