use std::{
    collections::{hash_map::Entry, HashMap},
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

use crate::{cbox::Cbox, utils::{gen_psk, NanoidEntry}};

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
    pub s1: u32,
    pub s2: u32,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct Assignment {
    offset: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Server {
    id: Nanoid,
    pub name: String,
    pub endpoint: String,
    pub protocol: Protocol,
    pub dns: String,
    pub port: u16,
    secret: StaticSecret,

    /// Client network
    /// When editing, the size can only stay the same or increase, never shrink.
    client_net: Ipv4Cidr,

    /// Maps device ID to its range offset
    assignments: HashMap<Nanoid, Assignment>,

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
    pub cbox: Option<Cbox>
}

impl Vault {
    pub fn new() -> Vault {
        Vault {
            servers: HashMap::new(),
            devices: HashMap::new(),
            cbox: None
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
        let device_pubkey = PublicKey::from(&self.secret);
        let pubkey = PublicKey::from(&server.secret);

        writeln!(&mut s, "[Interface]")?;
        writeln!(&mut s, "Address = {}", inet)?;
        writeln!(
            &mut s,
            "PrivateKey = {}",
            BASE64_STANDARD.encode(self.secret.as_bytes())
        )?;
        writeln!(
            &mut s,
            "# PublicKey = {}",
            BASE64_STANDARD.encode(device_pubkey.as_bytes())
        )?;
        writeln!(&mut s, "DNS = {}", "1.1.1.1")?;

        match &server.protocol {
            Protocol::AmneziaWG(awg) => {
                writeln!(&mut s, "Jc = {}", awg.jc)?;
                writeln!(&mut s, "Jmin = {}", awg.jmin)?;
                writeln!(&mut s, "Jmax = {}", awg.jmax)?;
                writeln!(&mut s, "S1 = {}", awg.s1)?;
                writeln!(&mut s, "S2 = {}", awg.s2)?;
                writeln!(&mut s, "H1 = {}", awg.h1)?;
                writeln!(&mut s, "H2 = {}", awg.h2)?;
                writeln!(&mut s, "H3 = {}", awg.h3)?;
                writeln!(&mut s, "H4 = {}", awg.h4)?;
            }
            _ => {}
        };

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
    pub fn new(
        name: String,
        endpoint: String,
        protocol: Protocol,
        dns: String,
        port: u16,
        client_net: Ipv4Cidr,
    ) -> Server {
        let secret = StaticSecret::random();

        // minus two because the first is zero and server uses the next one
        let client_net_size = client_net.iter().count() - 2;

        let regvec = bitvec![u64, Lsb0; 0; client_net_size];

        Server {
            id: Nanoid::new(),
            name,
            endpoint,
            dns,
            port,
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

    pub fn own_address(&self) -> Ipv4Addr {
        self.client_net.iter().nth(1).unwrap().address()
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

    pub fn generate_config(&self, vault: &Vault) -> Result<String> {
        let mut s = String::with_capacity(2048);

        let addr = self.own_address();
        let pubkey = PublicKey::from(&self.secret);

        writeln!(&mut s, "[Interface]")?;
        writeln!(
            &mut s,
            "PrivateKey = {}",
            BASE64_STANDARD.encode(self.secret.as_bytes())
        )?;
        writeln!(
            &mut s,
            "# PublicKey = {}",
            BASE64_STANDARD.encode(pubkey.as_bytes())
        )?;
        writeln!(&mut s, "Address = {}", addr)?;
        writeln!(&mut s, "ListenPort = {}", self.port)?;

        match &self.protocol {
            Protocol::AmneziaWG(awg) => {
                writeln!(&mut s, "Jc = {}", awg.jc)?;
                writeln!(&mut s, "Jmin = {}", awg.jmin)?;
                writeln!(&mut s, "Jmax = {}", awg.jmax)?;
                writeln!(&mut s, "S1 = {}", awg.s1)?;
                writeln!(&mut s, "S2 = {}", awg.s2)?;
                writeln!(&mut s, "H1 = {}", awg.h1)?;
                writeln!(&mut s, "H2 = {}", awg.h2)?;
                writeln!(&mut s, "H3 = {}", awg.h3)?;
                writeln!(&mut s, "H4 = {}", awg.h4)?;
            }
            _ => {}
        };

        writeln!(&mut s, "PostUp = {}", "iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")?;
        writeln!(&mut s, "PostDown = {}", "iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE")?;

        for (device_id, assn) in &self.assignments {
            let device = vault
                .devices
                .get(device_id)
                .expect("Device with assignment not found in vault");
            let inet = Ipv4Inet::new(self.offset_to_address(assn.offset).unwrap(), 32)?;

            writeln!(&mut s, "\n[Peer]")?;
            writeln!(&mut s, "# DEVICE {}", device)?;
            writeln!(&mut s, "PublicKey = {}", device.public_key_b64())?;
            writeln!(
                &mut s,
                "PresharedKey = {}",
                BASE64_STANDARD.encode(device.psk)
            )?;
            writeln!(&mut s, "AllowedIPs = {}", inet)?;
        }

        s.shrink_to_fit();
        Ok(s)
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
        match self.client_net.iter().nth(offset as usize + 2) {
            Some(n) => Some(n.address()),
            None => None,
        }
    }

    fn register_or_get_device_assignment(&mut self, device_id: &Nanoid) -> Result<Assignment> {
        match self.assignments.get(&device_id) {
            Some(assignment) => return Ok(assignment.clone()),
            None => {}
        };

        let offset = match self.allocate_offset() {
            Err(IPAllocError::PoolExhausted) => return Err(anyhow!("Offset pool exhausted")),
            Ok(v) => v,
        };

        let assignment = Assignment { offset };

        self.assignments.insert(*device_id, assignment.clone());

        Ok(assignment)
    }

    fn register_or_get_device_addr(&mut self, device_id: &Nanoid) -> Result<Ipv4Addr> {
        match self.register_or_get_device_assignment(device_id) {
            Ok(assignment) => self
                .offset_to_address(assignment.offset)
                .ok_or_else(|| anyhow!("Failed to convert offset to IPv4")),
            Err(e) => Err(e),
        }
    }

    fn unregister_device(&mut self, device_id: &Nanoid) {
        match self.assignments.get(&device_id) {
            Some(assignment) => {
                self.free_offset(assignment.offset);
            }
            None => {}
        }

        self.assignments.remove(device_id);
    }
}

impl AWGParams {
    pub fn generate() -> AWGParams {
        let jmin = random_range(3..=700);

        AWGParams {
            jc: random_range(3..=127),
            jmin: jmin,
            jmax: random_range((jmin + 1)..=1270),
            s1: random_range(3..=127),
            s2: random_range(3..=127),
            h1: random_range(0x10000011..=0x7FFFFF00),
            h2: random_range(0x10000011..=0x7FFFFF00),
            h3: random_range(0x10000011..=0x7FFFFF00),
            h4: random_range(0x10000011..=0x7FFFFF00),
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
        match self.devices.entry(device.id) {
            Entry::Vacant(v) => {
                v.insert(device);
                Ok(())
            }
            Entry::Occupied(_) => Err(anyhow!("Server already added!")),
        }
    }

    pub fn add_server(&mut self, server: Server) -> Result<()> {
        match self.servers.entry(server.id) {
            Entry::Vacant(v) => {
                v.insert(server);
                Ok(())
            }
            Entry::Occupied(_) => Err(anyhow!("Server already added!")),
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
        match self.servers.remove(server_id) {
            Some(_) => Ok(()),
            None => Err(anyhow!("Server does not exist!")),
        }
    }

    pub fn generate_device_config(
        &mut self,
        device_id: &Nanoid,
        server_id: &Nanoid,
    ) -> Result<String> {
        let device = self
            .devices
            .get(device_id)
            .ok_or_else(|| anyhow!("Device not found!"))?;
        let server = self
            .servers
            .get_mut(server_id)
            .ok_or_else(|| anyhow!("Server not found!"))?;

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
