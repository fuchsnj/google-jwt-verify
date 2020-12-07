use serde::Deserialize;

use crate::claims::Claims;

pub trait Validator {
    type RequiredClaims: Claims;
    type IdPayload: for<'a> Deserialize<'a>;
    fn claims_are_valid(&self, claims: &Self::RequiredClaims) -> bool;
}
