use serde::Deserialize;

use crate::error::TokenClaimsError;

pub trait Validator {
    type RequiredClaims: for<'a> Deserialize<'a> + Clone;
    type IdPayload: for<'a> Deserialize<'a>;
    type ClaimsError: TokenClaimsError;
    fn validate_claims(
        &self,
        claims: &Self::RequiredClaims,
        current_timestamp: u64,
    ) -> Result<(), Self::ClaimsError>;
}
