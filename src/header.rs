use serde_derive::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct Header {
    #[serde(rename = "kid")]
    pub key_id: String,
}