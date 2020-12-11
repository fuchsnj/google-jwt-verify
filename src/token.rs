use crate::key_provider::FirebaseClaimsError;
use serde_derive::Deserialize;
use thiserror::Error;

#[derive(Debug, PartialEq)]
pub struct Token<P, C> {
    required_claims: C,
    payload: P,
}

impl<P, C: Clone> Token<P, C> {
    pub fn new(required_claims: C, payload: P) -> Token<P, C> {
        Token {
            required_claims,
            payload,
        }
    }
    pub fn get_claims(&self) -> C {
        self.required_claims.clone()
    }
    pub fn get_payload(&self) -> &P {
        &self.payload
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct FirebaseRequiredClaims {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "aud")]
    audience: String,

    #[serde(rename = "auth_time")]
    auth_time: u64,

    #[serde(rename = "iat")]
    issued_at: u64,

    #[serde(rename = "exp")]
    expires_at: u64,
}

impl FirebaseRequiredClaims {
    pub fn validate_for_project(
        &self,
        project_id: &str,
        current_timestamp: u64,
    ) -> Result<(), FirebaseClaimsError> {
        let expected = format!("https://securetoken.google.com/{}", project_id);
        if self.audience != project_id {
            Err(FirebaseClaimsError::InvalidAudience {
                expected: project_id.into(),
                found: self.audience.clone(),
            })
        } else if self.issuer != expected {
            Err(FirebaseClaimsError::InvalidIssuer {
                found: self.issuer.clone(),
                expected,
            })
        } else if current_timestamp < self.auth_time {
            Err(FirebaseClaimsError::AuthenticatedInTheFuture {
                now: current_timestamp,
                auth_time: self.auth_time,
            })
        } else if current_timestamp < self.issued_at {
            Err(FirebaseClaimsError::IssuedInTheFuture {
                iat: self.issued_at,
                now: current_timestamp,
            })
        } else if self.expires_at < current_timestamp {
            Err(FirebaseClaimsError::Expired {
                exp: self.expires_at,
                now: current_timestamp,
            })
        } else {
            Ok(())
        }
    }
    pub fn get_subject(&self) -> String {
        self.subject.clone()
    }
}

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub struct GoogleSigninRequiredClaims {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "aud")]
    audience: String,

    #[serde(rename = "azp")]
    android_audience: String,

    #[serde(rename = "iat")]
    issued_at: u64,

    #[serde(rename = "exp")]
    expires_at: u64,
}

impl GoogleSigninRequiredClaims {
    pub fn validate_for_client(
        &self,
        client_id: &str,
        current_timestamp: u64,
    ) -> Result<(), GoogleSigninClaimsError> {
        let allowed = ["https://accounts.google.com", "accounts.google.com"];
        if self.audience != client_id {
            Err(GoogleSigninClaimsError::InvalidAudience {
                found: self.audience.clone(),
                expected: client_id.into(),
            })
        } else if !allowed.contains(&self.issuer.as_str()) {
            Err(GoogleSigninClaimsError::InvalidIssuer {
                found: self.issuer.clone(),
                allowed,
            })
        } else if self.expires_at < current_timestamp {
            Err(GoogleSigninClaimsError::Expired {
                now: current_timestamp,
                exp: self.expires_at,
            })
        } else if self.expires_at < self.issued_at {
            Err(GoogleSigninClaimsError::IssuedAfterExpiry {
                iss: self.issued_at,
                exp: self.expires_at,
            })
        } else {
            Ok(())
        }
    }
    pub fn get_issuer(&self) -> String {
        self.issuer.clone()
    }
    pub fn get_subject(&self) -> String {
        self.subject.clone()
    }
    pub fn get_audience(&self) -> String {
        self.audience.clone()
    }
    pub fn get_android_audience(&self) -> String {
        self.android_audience.clone()
    }
    pub fn get_issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn get_expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum GoogleSigninClaimsError {
    #[error("JWT audience claim ({found}) is not equal to the client ID (expected)")]
    InvalidAudience { found: String, expected: String },
    #[error("JWT issuer ({found}) is neither {} nor {}", .allowed[0], .allowed[1])]
    InvalidIssuer {
        found: String,
        allowed: [&'static str; 2],
    },
    #[error("JWT has expired. Current timestamp={now}. Expiration timestamp={exp}")]
    Expired { now: u64, exp: u64 },
    #[error("JWT was issued (timestamp={iss}) after expiration (timestamp={exp})")]
    IssuedAfterExpiry { iss: u64, exp: u64 },
}

#[derive(Deserialize, Clone, Debug)]
pub struct FirebaseIdPayload {
    name: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    phone_number: Option<String>,
    picture: Option<String>,
    sub: String,
}

impl FirebaseIdPayload {
    pub fn get_name(&self) -> &Option<String> {
        &self.name
    }
    pub fn get_email(&self) -> &Option<String> {
        &self.email
    }
    pub fn is_email_verified(&self) -> Option<bool> {
        self.email_verified
    }
    pub fn get_phone_number(&self) -> &Option<String> {
        &self.phone_number
    }
    pub fn get_picture(&self) -> &Option<String> {
        &self.picture
    }
    pub fn get_user_id(&self) -> &String {
        &self.sub
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct GoogleSigninIdPayload {
    email: String,
    email_verified: bool,
    name: String,
    picture: String,
    given_name: String,
    family_name: String,
    locale: String,
    hd: Option<String>,
}

impl GoogleSigninIdPayload {
    pub fn get_email(&self) -> String {
        self.email.clone()
    }
    pub fn is_email_verified(&self) -> bool {
        self.email_verified
    }
    pub fn get_name(&self) -> String {
        self.name.clone()
    }
    pub fn get_picture_url(&self) -> String {
        self.picture.clone()
    }
    pub fn get_given_name(&self) -> String {
        self.given_name.clone()
    }
    pub fn get_family_name(&self) -> String {
        self.family_name.clone()
    }
    pub fn get_locale(&self) -> String {
        self.locale.clone()
    }
    pub fn get_domain(&self) -> Option<String> {
        self.hd.clone()
    }
}
