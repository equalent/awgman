use std::{
    collections::HashMap,
    fmt::{Display, Write},
    net::Ipv4Addr,
};

use anyhow::{anyhow, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use bitvec::{bitvec, field::BitField, order::Lsb0, vec::BitVec};
use cidr::{Ipv4Cidr, Ipv4Inet};
use nid::Nanoid;
use rand::{random_range, rng, Rng};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::utils::{gen_psk, NanoidEntry};

pub type PSK = [u8; 32];

#[derive(Debug)]
pub enum IPAllocError {
    PoolExhausted,
}

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
    pub jmax: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Server {
    id: Nanoid,
    pub name: String,
    pub endpoint: String,
    pub protocol: Protocol,
    secret: StaticSecret,

    /// Client network
    /// When editing, the size can only stay the same or increase, never shrink.
    client_net: Ipv4Cidr,

    /// Maps device ID to its range offset
    assignments: HashMap<Nanoid, u32>,

    /// Bitmap of address allocations
    bitmap: BitVec<u64, Lsb0>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Device {
    id: Nanoid,
    pub name: String,
    pub user: String,
    secret: StaticSecret,
    psk: PSK,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    servers: HashMap<Nanoid, Server>,
    devices: HashMap<Nanoid, Device>,
}

impl Vault {
    pub fn new() -> Vault {
        Vault {
            servers: HashMap::new(),
            devices: HashMap::new(),
        }
    }
}

impl Device {
    pub fn new(name: String, user: String) -> Result<Device> {
        let secret = StaticSecret::random();
        let psk = gen_psk()?;

        Ok(Device {
            id: Nanoid::new(),
            name,
            user,
            secret,
            psk,
        })
    }

    pub fn id(&self) -> Nanoid {
        self.id
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn public_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.public_key().to_bytes())
    }

    pub fn generate_config(&self, server: &mut Server) -> Result<String> {
        let mut s = String::with_capacity(2048);

        let addr = server.register_or_get_device_addr(&self.id)?;
        let inet = Ipv4Inet::new(addr, server.client_net.network_length())?;

        writeln!(&mut s, "[Interface]")?;
        writeln!(&mut s, "Address = {}", inet)?;
        writeln!(
            &mut s,
            "PrivateKey = {}",
            BASE64_STANDARD.encode(self.secret.as_bytes())
        )?;

        let pubkey = PublicKey::from(&server.secret);

        writeln!(&mut s, "\n[Peer]")?;
        writeln!(
            &mut s,
            "PublicKey = {}",
            BASE64_STANDARD.encode(pubkey.as_bytes())
        )?;
        writeln!(
            &mut s,
            "PresharedKey = {}",
            BASE64_STANDARD.encode(self.psk)
        )?;
        writeln!(&mut s, "AllowedIPs = {}", "0.0.0.0/0, ::/0")?;
        writeln!(&mut s, "Endpoint = {}", server.endpoint)?;

        Ok(s)
    }
}

impl Server {
    pub fn new(name: String, endpoint: String, protocol: Protocol, client_net: Ipv4Cidr) -> Server {
        let secret = StaticSecret::random();

        // minus one because server uses the first one
        let client_net_size = client_net.iter().count() - 1;

        let regvec = bitvec![u64, Lsb0; 0; client_net_size];

        Server {
            id: Nanoid::new(),
            name,
            endpoint,
            protocol,
            secret,
            client_net,
            assignments: HashMap::new(),
            bitmap: regvec,
        }
    }

    pub fn id(&self) -> Nanoid {
        self.id
    }

    pub fn client_net(&self) -> Ipv4Cidr {
        self.client_net
    }

    pub fn client_net_available(&self) -> usize {
        self.bitmap.count_zeros()
    }

    pub fn client_net_used(&self) -> usize {
        self.bitmap.count_ones()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn public_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.public_key().to_bytes())
    }

    fn allocate_offset(&mut self) -> Result<u32, IPAllocError> {
        let len = self.bitmap.len();
        let mut rng = rng();

        // --- Phase 1: Random sampling ---
        const MAX_RANDOM_TRIES: usize = 32;
        for _ in 0..MAX_RANDOM_TRIES {
            let idx = rng.random_range(0..len);
            if !self.bitmap[idx] {
                self.bitmap.set(idx, true);
                return Ok(idx as u32);
            }
        }

        // --- Phase 2: Fallback sequential scan ---
        for (chunk_idx, chunk) in self.bitmap.chunks_exact(64).enumerate() {
            let word: u64 = chunk.load();
            if word != u64::MAX {
                let bit = (!word).trailing_zeros() as usize;
                let idx = chunk_idx * 64 + bit;
                if idx < len {
                    self.bitmap.set(idx, true);
                    return Ok(idx as u32);
                }
            }
        }

        Err(IPAllocError::PoolExhausted)
    }

    fn free_offset(&mut self, offset: u32) {
        let idx = offset as usize;
        if idx < self.bitmap.len() {
            self.bitmap.set(idx, false);
        }
    }

    fn offset_to_address(&self, offset: u32) -> Option<Ipv4Addr> {
        match self.client_net.iter().nth(offset as usize + 1) {
            Some(n) => Some(n.address()),
            None => None,
        }
    }

    fn register_or_get_device_offset(&mut self, device_id: &Nanoid) -> Result<u32> {
        match self.assignments.get(&device_id) {
            Some(offset) => return Ok(*offset),
            None => {}
        };

        let offset = match self.allocate_offset() {
            Err(IPAllocError::PoolExhausted) => return Err(anyhow!("Offset pool exhausted")),
            Ok(v) => v,
        };

        self.assignments.insert(*device_id, offset);

        Ok(offset)
    }

    fn register_or_get_device_addr(&mut self, device_id: &Nanoid) -> Result<Ipv4Addr> {
        match self.register_or_get_device_offset(device_id) {
            Ok(offset) => self
                .offset_to_address(offset)
                .ok_or_else(|| anyhow!("Failed to convert offset to IPv4")),
            Err(e) => Err(e),
        }
    }

    fn unregister_device(&mut self, device_id: &Nanoid) {
        match self.assignments.get(&device_id) {
            Some(offset) => {
                self.free_offset(*offset);
            }
            None => {}
        }
    }
}

impl AWGParams {
    pub fn generate() -> AWGParams {
        let jmin = random_range(3..=700);

        AWGParams {
            jc: random_range(3..=127),
            jmin: jmin,
            jmax: random_range((jmin + 1)..=1270),
        }
    }
}

impl Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pubkey = PublicKey::from(&self.secret).to_bytes();
        write!(
            f,
            "{} [ID: {}] / {}",
            self.name,
            self.id,
            BASE64_STANDARD.encode(pubkey)
        )
    }
}

impl Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pubkey = PublicKey::from(&self.secret).to_bytes();
        write!(
            f,
            "{} [ID: {}] / {}",
            self.name,
            self.id,
            BASE64_STANDARD.encode(pubkey)
        )
    }
}

impl PartialEq for Device {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PartialEq for Server {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Vault {
    pub fn servers(&self) -> &HashMap<Nanoid, Server> {
        &self.servers
    }

    pub fn devices(&self) -> &HashMap<Nanoid, Device> {
        &self.devices
    }

    pub fn add_device(&mut self, device: Device) -> Result<()> {
        match self.devices.insert(device.id, device) {
            Some(_) => Ok(()),
            None => Err(anyhow!("Device already added!"))
        }
    }

    pub fn add_server(&mut self, server: Server) -> Result<()> {
        match self.servers.insert(server.id, server) {
            Some(_) => Ok(()),
            None => Err(anyhow!("Server already added!"))
        }
    }

    pub fn remove_device(&mut self, device_id: &Nanoid) -> Result<()> {
        match self.devices.remove(device_id) {
            Some(_) => {}
            None => return Err(anyhow!("Device does not exist!")),
        };

        for server in self.servers.values_mut() {
            server.unregister_device(device_id);
        }

        Ok(())
    }

    pub fn remove_server(&mut self, server_id: &Nanoid) -> Result<()> {
        match  self.servers.remove(server_id) {
            Some(_) => Ok(()),
            None => Err(anyhow!("Server does not exist!")),
        }
    }

    pub fn generate_device_config(&mut self, device_id: &Nanoid, server_id: &Nanoid) -> Result<String> {
        let device = self.devices.get(device_id).ok_or_else(|| anyhow!("Device not found!"))?;
        let server = self.servers.get_mut(server_id).ok_or_else(|| anyhow!("Server not found!"))?;

        device.generate_config(server)
    }

    pub fn make_device_choice_vec(&self) -> Vec<NanoidEntry> {
        let mut v: Vec<NanoidEntry> = Vec::with_capacity(self.devices.len());

        for (_, device) in &self.devices {
            v.push(NanoidEntry {
                id: device.id(),
                display: device.to_string(),
            });
        }

        v
    }

    pub fn make_server_choice_vec(&self) -> Vec<NanoidEntry> {
        let mut v: Vec<NanoidEntry> = Vec::with_capacity(self.servers.len());

        for (_, server) in &self.servers {
            v.push(NanoidEntry {
                id: server.id(),
                display: server.to_string(),
            });
        }

        v
    }
}
