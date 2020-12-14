use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

pub fn current_timestamp() -> Result<u64, SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
}
