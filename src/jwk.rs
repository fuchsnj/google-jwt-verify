use crate::algorithm::Algorithm;
use crate::base64_decode;
use crate::error::Error;
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

    pub fn verify(&self, body: &[u8], signature: &[u8]) -> Result<(), Error> {
        match self.algorithm {
            Algorithm::RS256 => {
                // https://docs.rs/rsa/0.9.6/src/rsa/pkcs1v15.rs.html#561
                // https://en.wikipedia.org/wiki/PKCS_1#Schemes
                #[cfg(feature = "native-ssl")]
                {
                    use openssl::{
                        bn::BigNum, hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Verifier,
                    };
                    let n = BigNum::from_slice(&base64_decode(&self.n)?)?;
                    let e = BigNum::from_slice(&base64_decode(&self.e)?)?;
                    let key = PKey::from_rsa(Rsa::from_public_components(n, e)?)?;
                    let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
                    verifier.update(body)?;
                    verifier.verify(signature)?;
                }
                #[cfg(feature = "rust-ssl")]
                {
                    use rsa::{pkcs1v15::Pkcs1v15Sign, BigUint, RsaPublicKey};
                    use sha2::{Digest, Sha256};
                    let n = BigUint::from_bytes_be(&base64_decode(&self.n)?.as_ref());
                    let e = BigUint::from_bytes_be(&base64_decode(&self.e)?.as_ref());
                    let key = RsaPublicKey::new(n, e).map_err(Error::from)?;
                    let digest = Sha256::digest(body).to_vec();
                    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
                        .map_err(Error::from)?;
                }
                Ok(())
            }
            _ => Err(Error::UnsupportedAlgorithm(self.algorithm)),
        }
    }
}
