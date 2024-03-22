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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.decode(&input)
}
