use anyhow::{Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Cbox {
    pub key: String,
    pub endpoint: String,
}

#[derive(Serialize)]
struct CboxReq<'a> {
    name: &'a String,
    conf: &'a String,
    ttl: u32,
}

#[derive(Deserialize, Clone)]
pub struct CboxLink {
    pub full: String,
    pub short: String,
}

const CBOX_TTL: u32 = 3600; // 1 hour

impl Cbox {
    pub fn post(&self, name: &String, conf: &String) -> Result<CboxLink> {
        let req = CboxReq {
            name: name,
            conf: conf,
            ttl: CBOX_TTL,
        };

        Ok(ureq::post(self.endpoint.clone())
            .header("X-Cbox-Key", self.key.clone())
            .send_json(req)?
            .body_mut()
            .read_json::<CboxLink>()?)
    }
}
