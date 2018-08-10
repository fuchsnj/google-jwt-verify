#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate openssl;
extern crate base64;
extern crate reqwest;

#[cfg(test)]
mod test;

mod key_provider;
mod algorithm;
mod error;
mod jwk;
mod client;
mod token;

pub use client::Client;
pub use token::{Token, IdPayload, RequiredClaims};
pub use key_provider::{KeyProvider,GoogleKeyProvider};

fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(&input, base64::URL_SAFE)
}
