use serde::Deserialize;

pub trait Claims: Clone
where
    for<'a> Self: Deserialize<'a>,
{
    fn get_issued_at(&self) -> u64;
    fn get_expires_at(&self) -> u64;
}
