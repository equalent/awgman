use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

pub type PSK = [u8; 32];

#[repr(u16)]
#[derive(Serialize, Deserialize)]
pub enum Protocol {
    WireGuard = 0,
    AmneziaWG = 1
}

#[derive(Serialize, Deserialize)]
pub struct Server {
    pub address: IpAddr,
    pub endpoint: String,
    pub protocol: Protocol,
    pub secret: StaticSecret,
}

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub user: String,
    pub secret: StaticSecret,
    pub psk: PSK
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub servers: Vec<Server>,
    pub devices: Vec<Device>
}

impl Vault {
    pub fn new() -> Vault {
        Vault {
            servers: Vec::new(),
            devices: Vec::new()
        }
    }
}