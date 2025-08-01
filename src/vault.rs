use std::fmt::{Display, Write};

use base64::{prelude::BASE64_STANDARD, Engine};
use rand::random_range;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use subtle::ConstantTimeEq;
use anyhow::Result;

pub type PSK = [u8; 32];

#[repr(u8)]
#[derive(Serialize, Deserialize, Clone)]
pub enum Protocol {
    WireGuard = 0,
    AmneziaWG(AWGParams) = 1,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AWGParams {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Server {
    pub name: String,
    pub endpoint: String,
    pub protocol: Protocol,
    pub secret: StaticSecret
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Device {
    pub name: String,
    pub user: String,
    pub secret: StaticSecret,
    pub psk: PSK,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub servers: Vec<Server>,
    pub devices: Vec<Device>,
}

impl Vault {
    pub fn new() -> Vault {
        Vault {
            servers: Vec::new(),
            devices: Vec::new(),
        }
    }
}

impl Device {
    pub fn generate_config(&self, server: &Server) -> Result<String> {
        let mut s = String::with_capacity(2048);

        writeln!(&mut s, "[Interface]")?;
        writeln!(&mut s, "Address = {}", "10.0.0.3/24")?;
        writeln!(&mut s, "PrivateKey = {}", BASE64_STANDARD.encode(self.secret.as_bytes()))?;

        let pubkey = PublicKey::from(&server.secret);

        writeln!(&mut s, "\n[Peer]")?;
        writeln!(&mut s, "PublicKey = {}", BASE64_STANDARD.encode(pubkey.as_bytes()))?;
        writeln!(&mut s, "PresharedKey = {}", BASE64_STANDARD.encode(self.psk))?;
        writeln!(&mut s, "AllowedIPs = {}", "0.0.0.0/0, ::/0")?;
        writeln!(&mut s, "Endpoint = {}", server.endpoint)?;

        Ok(s)
    }
}

impl AWGParams {
    pub fn generate() -> AWGParams {
        let jmin = random_range(3..=700);

        AWGParams {
            jc: random_range(3..=127),
            jmin: jmin,
            jmax: random_range((jmin +1)..=1270)
        }
    }
}

impl Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pubkey = PublicKey::from(&self.secret).to_bytes();
        write!(
            f,
            "{} [{}] / {}",
            self.name,
            self.user,
            BASE64_STANDARD.encode(pubkey)
        )
    }
}

impl Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pubkey = PublicKey::from(&self.secret).to_bytes();
        write!(
            f,
            "{} [{}] / {}",
            self.name,
            self.endpoint,
            BASE64_STANDARD.encode(pubkey)
        )
    }
}

impl PartialEq for Device {
    fn eq(&self, other: &Self) -> bool {
        self.secret.to_bytes().ct_eq(&other.secret.to_bytes()).unwrap_u8() == 1
    }
}

impl PartialEq for Server {
    fn eq(&self, other: &Self) -> bool {
        self.secret.to_bytes().ct_eq(&other.secret.to_bytes()).unwrap_u8() == 1
    }
}
