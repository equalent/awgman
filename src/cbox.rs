use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Cbox {
    pub key: String,
    pub endpoint: String
}

impl Cbox {
    
}