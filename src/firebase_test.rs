#[cfg(feature = "async")]
use crate::key_provider::AsyncKeyProvider;
#[cfg(feature = "blocking")]
use crate::key_provider::KeyProvider;
use crate::{
    error::TokenValidationError,
    jwk::{JsonWebKey, JsonWebKeySet},
    key_provider::FirebaseClaimsError,
    Client, Error,
};
#[cfg(feature = "async")]
use async_trait::async_trait;

const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImI5ODI2ZDA5Mzc3N2NlMDA1ZTQzYTMyN2ZmMjAyNjUyMTQ1ZTk2MDQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vand0LXZlcmlmeSIsImF1ZCI6Imp3dC12ZXJpZnkiLCJhdXRoX3RpbWUiOjE2MDc1NjE4NzQsInVzZXJfaWQiOiJ0ZXN0Iiwic3ViIjoidGVzdCIsImlhdCI6MTYwNzU2MTg3NCwiZXhwIjoxNjA3NTY1NDc0LCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7fSwic2lnbl9pbl9wcm92aWRlciI6ImN1c3RvbSJ9fQ.ZM6-sQXruuHoC5RJkhDfP5klTz9Rd0-8RQreydNqg7rIP1C-5BYG2R6y-Iq6OCrq6IrOtgvJ0QOJu9lnZpeks-InJB0ACTOLLpT-0Rj1zSSYm1KxtXsfrJu99gRKqY21W8405mDg7rp4S2LSqSWZnw1_zPt9YhLfvSWqqubHIomXh2AipvcjQVnn1AgV4vfIJ0yG3aq8Kw8li1k5ZVHmq5XaS2Gh4nP-fWnDzSxr9_AgYoiNlsncVuhGGo81IKNsXbwFuWRXYFuVffvGIhVfsiMAVCCwLjoM72RoAAikXCv3AfUWdklLOL2tcUkK42sLqUofHdqPAgtO4m8f9XGpgA";

/// https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com at 2020/12/10 01:17 UTC
const JWKS: &str = r#"{
  "keys": [
    {
      "alg": "RS256",
      "use": "sig",
      "kid": "b9826d093777ce005e43a327ff202652145e9604",
      "n": "57ATt2MoR9swEFVy6cCW_cbswo6UxQZn8knRPrkOPwm6RfopXl35osZVF2n18D2U62zeMDzgsoFMEWLYbP6kXn2OK2ABoIKz5DDVAmhXvElKy0pXLNPSyqQ4aJydorBoZJbugCCODPmdgmYp96vbZ7FHY3ZyFK00Lt8v49cbfGDZA50NoUcR3k0PbpiLVVaDxM34jTHr9U97hRyebnbbKTaoBI_crRzDL9yaWOpfBVpQv_5oXhhKUKzzJLOMMnkiMJ0VbM2iA8RbHNlmyRbY01Xhd0aEVBTDt56kFGzR3CXc1lYO0jfwYOdtfwNJ6eef-qg3i4Sog5vreMMJ2FCVyQ",
      "e": "AQAB",
      "kty": "RSA"
    },
    {
      "e": "AQAB",
      "alg": "RS256",
      "kty": "RSA",
      "n": "hsMFtQ6M-08j5LMBaCNp9FDNeNwuMNv4KwRo7BRTtUI-cjAtIJFgT57dLNsywu0IMArnhl0VlD7ChRFXs8x3vtRg10vQackII78-wD1zx8YRlNCLVLxDbDogOAMHIWhAYIcowSU8fOaMzQsJLnwu_ZT4BkJGwj01P59x2KufnDW9gxR52sp5otAfESYl7w3Ay49JZCPqpEoCv79M9lXOiEWzvcR9woxOw2L-PDDP0V4lMS3Wyw38zqNRuPVSdCWB15e_pAl3aSelV21pJBHvTPfrPJ9Ok3TBybXx_-yq4TEKYSZTmzYoKOT81T4pD4C4uejaQy_6liq2oua-N-gUlw",
      "kid": "696aa74c81be60b294855a9a5ee9b8698e2abec1",
      "use": "sig"
    }
  ]
}"#;

const PROJECT_ID: &str = "jwt-verify";

const BEFORE_AUTHENTICATING: u64 = 1607561000;

const BETWEEN_AUTHENTICATING_AND_EXPIRATION: u64 = 1607562079;

const AFTER_EXPIRATION: u64 = 1607566000;

#[derive(Default)]
struct TestProvider;

#[cfg(feature = "blocking")]
impl KeyProvider for TestProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        let set: JsonWebKeySet = serde_json::from_str(JWKS).unwrap();
        Ok(set.get_key(key_id))
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl AsyncKeyProvider for TestProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Option<JsonWebKey>, ()> {
        let set: JsonWebKeySet = serde_json::from_str(JWKS).unwrap();
        Ok(set.get_key(key_id))
    }
}

#[cfg(feature = "blocking")]
#[test]
fn valid_firebase_token() {
    let client = Client::firebase_builder(PROJECT_ID)
        .custom_key_provider(TestProvider)
        .unsafe_mock_timestamp(BETWEEN_AUTHENTICATING_AND_EXPIRATION)
        .build();
    let id_token = client.verify_id_token(TOKEN).unwrap();
    assert_eq!(id_token.get_claims().get_subject(), "test");
}

#[cfg(feature = "blocking")]
#[test]
fn expired_firebase_token() {
    let client = Client::firebase_builder(PROJECT_ID)
        .custom_key_provider(TestProvider)
        .unsafe_mock_timestamp(AFTER_EXPIRATION)
        .build();
    assert_eq!(
        client.verify_id_token(TOKEN).unwrap_err(),
        Error::InvalidToken(TokenValidationError::Claims(FirebaseClaimsError::Expired {
            now: AFTER_EXPIRATION,
            exp: 1607565474
        }))
    );
}

#[cfg(feature = "blocking")]
#[test]
fn firebase_token_authenticated_in_the_future() {
    let client = Client::firebase_builder(PROJECT_ID)
        .custom_key_provider(TestProvider)
        .unsafe_mock_timestamp(BEFORE_AUTHENTICATING)
        .build();
    assert_eq!(
        client.verify_id_token(TOKEN).unwrap_err(),
        Error::InvalidToken(TokenValidationError::Claims(
            FirebaseClaimsError::AuthenticatedInTheFuture {
                auth_time: 1607561874,
                now: BEFORE_AUTHENTICATING
            }
        ))
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn valid_firebase_token_async() {
    let client = Client::firebase_builder(PROJECT_ID)
        .custom_key_provider(TestProvider)
        .unsafe_mock_timestamp(BETWEEN_AUTHENTICATING_AND_EXPIRATION)
        .tokio()
        .build();
    let id_token = client.verify_id_token(TOKEN).await.unwrap();
    assert_eq!(id_token.get_claims().get_subject(), "test");
}

#[cfg(feature = "async")]
#[tokio::test]
async fn expired_firebase_token_async() {
    let client = Client::firebase_builder(PROJECT_ID)
        .custom_key_provider(TestProvider)
        .unsafe_mock_timestamp(AFTER_EXPIRATION)
        .tokio()
        .build();
    assert_eq!(
        client.verify_id_token(TOKEN).await.unwrap_err(),
        Error::InvalidToken(TokenValidationError::Claims(FirebaseClaimsError::Expired {
            now: AFTER_EXPIRATION,
            exp: 1607565474
        }))
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn firebase_token_authenticated_in_the_future_async() {
    let client = Client::firebase_builder(PROJECT_ID)
        .custom_key_provider(TestProvider)
        .unsafe_mock_timestamp(BEFORE_AUTHENTICATING)
        .tokio()
        .build();
    assert_eq!(
        client.verify_id_token(TOKEN).await.unwrap_err(),
        Error::InvalidToken(TokenValidationError::Claims(
            FirebaseClaimsError::AuthenticatedInTheFuture {
                auth_time: 1607561874,
                now: BEFORE_AUTHENTICATING
            }
        ))
    );
}
