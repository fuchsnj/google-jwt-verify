use std::fmt::Debug;

use serde::Deserialize;

use crate::error::TokenClaimsError;

pub trait Validator {
    type RequiredClaims: for<'a> Deserialize<'a> + Clone + Debug;
    type IdPayload: for<'a> Deserialize<'a> + Debug;
    type ClaimsError: TokenClaimsError;
    fn validate_claims(
        &self,
        claims: &Self::RequiredClaims,
        current_timestamp: u64,
    ) -> Result<(), Self::ClaimsError>;
}
