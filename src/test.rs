use std::sync::Arc;

use super::*;
#[cfg(feature = "async")]
use crate::client::TokioClient;
use crate::error::Error;
use crate::jwk::JsonWebKey;
use crate::jwk::JsonWebKeySet;
#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::KeyProvider;
#[cfg(feature = "async")]
use futures::future::join_all;

#[cfg(feature = "async")]
use async_trait::async_trait;

const TOKEN: &'static str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA5YmNmODAyOGUwNjUzN2Q0ZDNhZTRkODRmNWM1YmFiY2YyYzBmMGEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzNDk4Nzk2NDE2OTEtOXZnN2JnYnVuNjJkNGE2MnZwc2ZzMjRvZ3VndWFuazYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIzNDk4Nzk2NDE2OTEtOXZnN2JnYnVuNjJkNGE2MnZwc2ZzMjRvZ3VndWFuazYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDU5MDc5MDAwMDgxNzA4NzE1ODYiLCJlbWFpbCI6ImRhbi5qYW1lcy5iYXVtYW5uQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE3MTA5NDcwOTUsIm5hbWUiOiJEYW4gQmF1bWFubiIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NKLXBGVHZTQkg1QlZISUxWZUVyQ0lpN1BYLUV6Q3NydzlMM05SX0xfRnA9czk2LWMiLCJnaXZlbl9uYW1lIjoiRGFuIiwiZmFtaWx5X25hbWUiOiJCYXVtYW5uIiwiaWF0IjoxNzEwOTQ3Mzk1LCJleHAiOjE3MTA5NTA5OTUsImp0aSI6ImRlNjg1MTk5ZTIxZDE5YjNlY2MyMTFlMDZjNGQ4NzRiNWFlMDhiMWUifQ.YdFwUBPlZExRZBlhZgaO9szNlm1Ffe3TNt8MauK7p30qikFo_EN6eKneVWS_TnpO1XtJoeeDsRDvewUoF0eQrN_G-eeVHl7Gsg5i6vgMYqNxObpwHh4oQaUNnUhTykNSjLuShB3FuBbq0NF6W6kC2UHwYqWmK360HpQjKF244zH2H0maLP5m1JIXdDSZb5KFSrXxGIIJpq2TCpz0JxdnPh9R4CzM_GgWnzwELO_nw3yyWYwQ1PCTyHg-RG6Xs-a8ZCPtLkgdeapqbapTnpBRqkIzbC97yw6WK7So1mQ3fNBTwLCygqfHcgJa_Snlgdl43pcVpbrFKFh8NTP7iW_N-Q";
const JWKS: &'static str = r#"{
  "keys": [
    {
      "use": "sig",
      "e": "AQAB",
      "n": "vdtZ3cfuh44JlWkJRu-3yddVp58zxSHwsWiW_jpaXgpebo0an7qY2IEs3D7kC186Bwi0T7Km9mUcDbxod89IbtZuQQuhxlgaXB-qX9GokNLdqg69rUaealXGrCdKOQ-rOBlNNGn3M4KywEC98KyQAKXe7prs7yGqI_434rrULaE7ZFmLAzsYNoZ_8l53SGDiRaUrZkhxXOEhlv1nolgYGIH2lkhEZ5BlU53BfzwjO-bLeMwxJIZxSIOy8EBIMLP7eVu6AIkAr9MaDPJqeF7n7Cn8yv_qmy51bV-INRS-HKRVriSoUxhQQTbvDYYvJzHGYu_ciJ4oRYKkDEwxXztUew",
      "alg": "RS256",
      "kty": "RSA",
      "kid": "09bcf8028e06537d4d3ae4d84f5c5babcf2c0f0a"
    },
    {
      "n": "y48N6JB-AKq1-Rv4SkwBADU-hp4zXHU-NcCUwxD-aS9vr4EoT9qrjoJ-YmkaEpq9Bmu1yXZZK_h_9QS3xEsO8Rc_WSvIQCJtIaDQz8hxk4lUjUQjMB4Zf9vdTmf8KdktI9tCYCbuSbLC6TegjDM9kbl9CNs3m9wSVeO_5JXJQC0Jr-Oj7Gz9stXm0Co3f7RCxrD08kLelXaAglrd5TeGjZMyViC4cw1gPaj0Cj6knDn8UlzR_WuBpzs_ies5BrbzX-yht0WfnhXpdpiGNMbpKQD04MmPdMCYq8ENF7q5_Ok7dPsVj1vHA6vFGnf7qE3smD157szsnzn0NeXIbRMnuQ",
      "kty": "RSA",
      "use": "sig",
      "kid": "adf5e710edfebecbefa9a61495654d03c0b8edf8",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}"#;
const AUDIENCE: &'static str =
    "349879641691-9vg7bgbun62d4a62vpsfs24oguguank6.apps.googleusercontent.com";
const EMAIL: &'static str = "dan.james.baumann@gmail.com";
const KIDS: [&str; 2] = [
    "09bcf8028e06537d4d3ae4d84f5c5babcf2c0f0a",
    "a748e9f767159f667a0223318de0b2329e544362",
];

#[derive(Default)]
struct TestKeyProvider {
    call_count: Arc<std::sync::RwLock<u8>>,
}

#[cfg(feature = "blocking")]
impl KeyProvider for TestKeyProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        let set: JsonWebKeySet = serde_json::from_str(JWKS).unwrap();
        *self.call_count.write().unwrap() += 1;
        Ok(set.get_key(key_id))
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncKeyProvider for TestKeyProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        let set: JsonWebKeySet = serde_json::from_str(JWKS).unwrap();
        *self.call_count.write().unwrap() += 1;
        Ok(set.get_key(key_id))
    }
}

#[cfg(feature = "blocking")]
#[test]
pub fn decode_keys() {
    for kid in KIDS.iter() {
        TestKeyProvider::default().get_key(kid).unwrap();
    }
}

#[cfg(feature = "blocking")]
#[test]
pub fn test_client() {
    let client = Client::builder(AUDIENCE)
        .custom_key_provider(TestKeyProvider::default())
        .build();
    assert_eq!(client.verify_token(TOKEN).map(|_| ()), Err(Error::Expired));
}

#[cfg(feature = "blocking")]
#[test]
pub fn test_client_invalid_client_id() {
    let client = Client::builder("invalid client id")
        .custom_key_provider(TestKeyProvider::default())
        .build();
    let result = client.verify_token(TOKEN).map(|_| ());
    assert_eq!(
        result,
        Err(Error::InvalidToken(error::InvalidError::InvalidClaims(
            "aud".to_string()
        )))
    )
}

#[cfg(feature = "blocking")]
#[test]
pub fn test_id_token() {
    let client = Client::builder(AUDIENCE)
        .custom_key_provider(TestKeyProvider::default())
        .unsafe_ignore_expiration()
        .build();
    let id_token = client
        .verify_id_token(TOKEN)
        .expect("id token should be valid");
    assert_eq!(id_token.get_claims().get_audience(), AUDIENCE);
    assert_eq!(id_token.get_payload().get_domain(), None);
    assert_eq!(id_token.get_payload().get_email(), EMAIL);
}

#[cfg(feature = "async")]
#[tokio::test]
async fn decode_keys_async() {
    for kid in KIDS.iter() {
        TestKeyProvider::default().get_key_async(kid).await.unwrap();
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_client_async() {
    let client = TokioClient::builder(AUDIENCE)
        .custom_key_provider(TestKeyProvider::default())
        .build();
    assert_eq!(
        client.verify_token_async(TOKEN).await.map(|_| ()),
        Err(Error::Expired)
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_client_invalid_client_id_async() {
    let client = TokioClient::builder("invalid client id")
        .custom_key_provider(TestKeyProvider::default())
        .build();
    let result = client.verify_token_async(TOKEN).await.map(|_| ());
    assert_eq!(
        result,
        Err(Error::InvalidToken(error::InvalidError::InvalidClaims(
            "aud".to_string()
        )))
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_id_token_async() {
    let client = TokioClient::builder(AUDIENCE)
        .custom_key_provider(TestKeyProvider::default())
        .unsafe_ignore_expiration()
        .build();
    let id_token = client
        .verify_id_token_async(TOKEN)
        .await
        .expect("id token should be valid");
    assert_eq!(id_token.get_claims().get_audience(), AUDIENCE);
    assert_eq!(id_token.get_payload().get_domain(), None);
    assert_eq!(id_token.get_payload().get_email(), EMAIL);
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_deadlock_prevention() {
    let client = TokioClient::builder(AUDIENCE)
        .unsafe_ignore_expiration()
        .build();
    join_all((0..10u8).map(|_| verify_token_async(&client))).await;
}

#[cfg(feature = "async")]
async fn verify_token_async(client: &TokioClient) {
    let result = client.verify_token_async(TOKEN).await;
    assert!(matches!(
        result,
        Err(Error::InvalidToken(error::InvalidError::Json(_)))
    ));
    // verify_token_async expects an empty payload, which serde_json tries to parse as '{}'
    // therefore the token is considered invalid due to failed json parsing:
    // invalid type: map, expected unit at line 1 column 0
}
