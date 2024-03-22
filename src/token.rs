use serde_derive::Deserialize;

#[derive(Debug, PartialEq)]
pub struct Token<P> {
    required_claims: RequiredClaims,
    payload: P,
}

impl<P> Token<P> {
    pub fn new(required_claims: RequiredClaims, payload: P) -> Token<P> {
        Token {
            required_claims,
            payload,
        }
    }
    pub fn get_claims(&self) -> RequiredClaims {
        self.required_claims.clone()
    }
    pub fn get_payload(&self) -> &P {
        &self.payload
    }
}

// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
#[derive(PartialEq, Deserialize, Debug, Clone)]
pub struct RequiredClaims {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "aud")]
    audience: String,

    #[serde(rename = "exp")]
    expires_at: u64,

    #[serde(rename = "nbf")]
    not_before: u64,

    #[serde(rename = "iat")]
    issued_at: u64,

    #[serde(rename = "jti")]
    jwt_id: String,

    #[serde(rename = "azp")]
    android_audience: String,
}

impl RequiredClaims {
    pub fn get_issuer(&self) -> String {
        self.issuer.clone()
    }
    pub fn get_subject(&self) -> String {
        self.subject.clone()
    }
    pub fn get_audience(&self) -> String {
        self.audience.clone()
    }
    pub fn get_expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn get_not_before(&self) -> u64 {
        self.not_before
    }
    pub fn get_issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn get_jwt_id(&self) -> String {
        self.jwt_id.clone()
    }
    pub fn get_android_audience(&self) -> String {
        self.android_audience.clone()
    }
}

// https://developers.google.com/identity/gsi/web/reference/html-reference#credential
#[derive(Deserialize, Clone, Debug)]
pub struct IdPayload {
    email: String,
    email_verified: bool,
    name: String,
    picture: String,
    given_name: String,
    family_name: String,
    locale: Option<String>,
    hd: Option<String>,
}

impl IdPayload {
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
    pub fn get_locale(&self) -> Option<String> {
        self.locale.clone()
    }
    pub fn get_domain(&self) -> Option<String> {
        self.hd.clone()
    }
}
