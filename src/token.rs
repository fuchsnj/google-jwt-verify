use serde_derive::Deserialize;

use crate::claims::Claims;

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
    pub fn valid_for_project(&self, project_id: &str) -> bool {
        self.audience == project_id
            && self.issuer == format!("https://securetoken.google.com/{}", project_id)
    }
}

impl Claims for FirebaseRequiredClaims {
    fn get_issued_at(&self) -> u64 {
        self.issued_at
    }
    fn get_expires_at(&self) -> u64 {
        self.expires_at
    }
    fn get_subject(&self) -> &str {
        self.subject.as_str()
    }
}

#[derive(Deserialize, Clone)]
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
    pub fn valid_for_client(&self, client_id: &str) -> bool {
        self.audience == client_id
            && ["https://accounts.google.com", "accounts.google.com"]
                .contains(&self.issuer.as_str())
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

impl Claims for GoogleSigninRequiredClaims {
    fn get_issued_at(&self) -> u64 {
        self.issued_at
    }
    fn get_expires_at(&self) -> u64 {
        self.expires_at
    }
    fn get_subject(&self) -> &str {
        self.subject.as_str()
    }
}

#[derive(Deserialize, Clone)]
pub struct FirebaseIdPayload {
    name: String,
}

#[derive(Deserialize, Clone)]
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
