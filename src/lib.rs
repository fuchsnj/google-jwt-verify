#[cfg(test)]
mod firebase_test;
#[cfg(test)]
mod test;

mod algorithm;
mod client;
mod error;
mod header;
mod jwk;
mod key_provider;
mod time;
mod token;
mod unverified_token;
mod validator;

pub use crate::client::{Client, FirebaseClient};
#[cfg(feature = "async")]
pub use crate::client::{FirebaseTokioClient, GoogleSigninTokioClient};
pub use crate::token::{
    GoogleSigninIdPayload as IdPayload, GoogleSigninRequiredClaims as RequiredClaims, Token,
};
pub use error::Error;
use token::GoogleSigninClaimsError;
use key_provider::FirebaseClaimsError;

pub type FirebaseError = Error<FirebaseClaimsError>;
pub type GoogleSigninError = Error<GoogleSigninClaimsError>;

fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(&input, base64::URL_SAFE)
}
