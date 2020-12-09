use crate::base64_decode;
use crate::{algorithm::Algorithm, error::VerificationError};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use serde_derive::Deserialize;

#[derive(Deserialize, Clone)]
pub struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

impl JsonWebKeySet {
    pub fn get_key(&self, id: &str) -> Option<JsonWebKey> {
        self.keys.iter().find(|key| key.id == id).cloned()
    }
}

#[derive(Deserialize, Clone)]
pub struct JsonWebKey {
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    #[serde(rename = "kid")]
    id: String,
    n: String,
    e: String,
}

impl JsonWebKey {
    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    pub fn verify(&self, body: &[u8], signature: &[u8]) -> Result<(), VerificationError> {
        match self.algorithm {
            Algorithm::RS256 => {
                let n = BigNum::from_slice(
                    &base64_decode(&self.n).map_err(|e| VerificationError::Modulus(e.into()))?,
                )
                .map_err(|e| VerificationError::Modulus(e.into()))?;
                let e = BigNum::from_slice(
                    &base64_decode(&self.e).map_err(|e| VerificationError::Exponent(e.into()))?,
                )
                .map_err(|e| VerificationError::Exponent(e.into()))?;
                let key = PKey::from_rsa(Rsa::from_public_components(n, e)?)?;
                let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
                verifier.update(body)?;
                verifier.verify(signature)?;
                Ok(())
            }
            _ => Err(VerificationError::UnsupportedAlgorithm(self.algorithm)),
        }
    }
}
