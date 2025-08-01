use atomicwrites::{AllowOverwrite, AtomicFile};
use bincode::{Decode, Encode};
use chacha20poly1305::{aead::AeadMutInPlace, KeyInit, XChaCha20Poly1305};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use std::{
    fs::OpenOptions,
    io::{Seek, Write},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use subtle::ConstantTimeEq;

use crate::vault::Vault;

#[derive(Encode, Decode, Debug)]
struct VersionHeader {
    magic: u32,
    version: u8,
}

#[derive(Encode, Decode, Debug)]
struct VaultHeaderV0 {
    nonce: VaultNonce,
    argon2: Argon2Params,
    salt: VaultSalt,
}

pub const MAGIC: u32 = u32::from_le_bytes(*b"RGVA");
pub const SECRET_LENGTH: usize = 32;
pub const SALT_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 24;

pub struct VaultFile {
    path: PathBuf,
    secret: SecretBox<VaultSecret>,
    argon2: Argon2Params,
    salt: VaultSalt,
    vault: Vault,
}

pub type VaultSecret = [u8; SECRET_LENGTH];
pub type VaultSalt = [u8; SALT_LENGTH];
pub type VaultNonce = [u8; NONCE_LENGTH];

#[derive(Encode, Decode, Clone, Debug)]
struct Argon2Params {
    version: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Argon2Params {
    const MINIMUM: Argon2Params = Argon2Params {
        version: 0x13,
        m_cost: 65536, // 64 MiB
        t_cost: 3,     // 3 iterations
        p_cost: 1,     // 1 lane
    };

    const DEFAULT: Argon2Params = Argon2Params {
        version: 0x13,
        m_cost: 102400, // 100 MiB
        t_cost: 4,      // 4 iterations
        p_cost: 8,      // 8 lanes
    };

    fn validate(&self) -> Result<()> {
        if self.version != Argon2Params::MINIMUM.version
            || self.m_cost < Argon2Params::MINIMUM.m_cost
            || self.t_cost < Argon2Params::MINIMUM.t_cost
            || self.p_cost < Argon2Params::MINIMUM.p_cost
        {
            Err(anyhow!(
                "Attempted to initialise Argon2 params with weak settings"
            ))
        } else {
            Ok(())
        }
    }

    fn to_argon(&self) -> Result<argon2::Params> {
        match argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(SECRET_LENGTH)) {
            Ok(v) => Ok(v),
            Err(e) => Err(anyhow!("Argon2 error: {}", e)),
        }
    }
}

impl VaultFile {
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn transact<F>(&mut self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Vault) -> Result<()>,
    {
        f(&mut self.vault)?;
        self.save()?;
        Ok(())
    }

    fn derive_secret(
        password: &SecretString,
        params: &Argon2Params,
        salt: &VaultSalt,
        secret_buf: &mut VaultSecret,
    ) -> Result<()> {
        let a2params = params.to_argon()?;
        let argon = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            params.version.try_into()?,
            a2params,
        );

        argon.hash_password_into(password.expose_secret().as_bytes(), salt, secret_buf)?;

        Ok(())
    }

    pub fn create(path: &Path, password: &SecretString) -> Result<VaultFile> {
        /*         let file = AtomicFile::new(path, AllowOverwrite);

        file.write(|f| f.write_all(b"HELLO"))?; */

        let a2params = Argon2Params::DEFAULT;
        let mut salt: VaultSalt = [0u8; SALT_LENGTH];

        getrandom::fill(&mut salt)?;

        let secret: SecretBox<VaultSecret> = SecretBox::init_with_mut(|v| {
            VaultFile::derive_secret(password, &a2params, &salt, v).unwrap();
        });

        let file = VaultFile {
            path: path.into(),
            secret: secret,
            argon2: a2params,
            salt: salt,
            vault: Vault::new(),
        };

        file.save()?;

        Ok(file)
    }

    pub fn open(path: &Path, password: &SecretString) -> Result<VaultFile> {
        let mut file = OpenOptions::new().read(true).open(path)?;

        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();

        let version_header: VersionHeader = bincode::decode_from_std_read(&mut file, config)?;

        if version_header.magic != MAGIC {
            return Err(anyhow!("Invalid magic"));
        }

        if version_header.version != 0 {
            return Err(anyhow!("Invalid header version"));
        }

        let header: VaultHeaderV0 = bincode::decode_from_std_read(&mut file, config)?;
        header.argon2.validate()?;

        let headers_size = file.stream_position()? as usize;

        let mut headers_buf: Vec<u8> = vec![0u8; headers_size];

        file.read_at(headers_buf.as_mut_slice(), 0)?;

        let secret: SecretBox<VaultSecret> = SecretBox::init_with_mut(|v| {
            VaultFile::derive_secret(password, &header.argon2, &header.salt, v).unwrap();
        });

        let ciphertext_size = file.metadata()?.len() as usize - headers_size;

        let mut buffer: Vec<u8> = vec![0u8; ciphertext_size];

        file.read_at(buffer.as_mut_slice(), headers_size as u64)?;

        let mut cipher = XChaCha20Poly1305::new(secret.expose_secret().into());

        cipher.decrypt_in_place(&header.nonce.into(), &headers_buf.as_slice(), &mut buffer)?;

        let vault: Vault = serde_cbor::from_slice(&buffer.as_slice())?;

        Ok(VaultFile {
            path: path.into(),
            secret: secret,
            argon2: header.argon2,
            salt: header.salt,
            vault: vault,
        })
    }

    pub fn save(&self) -> Result<()> {
        let file = AtomicFile::new(&self.path, AllowOverwrite);

        let mut buffer = serde_cbor::to_vec(&self.vault)?;

        let mut nonce: VaultNonce = VaultNonce::default();
        getrandom::fill(&mut nonce)?;

        let mut cipher = XChaCha20Poly1305::new(self.secret.expose_secret().into());

        let version_header = VersionHeader {
            magic: MAGIC,
            version: 0,
        };

        let header = VaultHeaderV0 {
            nonce: nonce,
            argon2: self.argon2.clone(),
            salt: self.salt,
        };

        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();

        let mut headers_buffer = vec![0u8; 0];

        bincode::encode_into_std_write(&version_header, &mut headers_buffer, config)?;
        bincode::encode_into_std_write(&header, &mut headers_buffer, config)?;

        cipher.encrypt_in_place(&nonce.into(), &headers_buffer, &mut buffer)?;

        file.write(|f| -> Result<()> {
            f.write_all(headers_buffer.as_slice())?;
            f.write_all(&buffer)?;

            Ok(())
        })
        .map_err(|e| anyhow!("Failed to write file: {}", e))?;

        Ok(())
    }

    pub fn is_password_correct(&self, password: SecretString) -> bool {
        let mut secret: VaultSecret = [0u8; SECRET_LENGTH];
        match VaultFile::derive_secret(&password, &self.argon2, &self.salt, &mut secret) {
            Err(_) => {
                return false;
            }
            _ => {}
        };

        secret.ct_eq(self.secret.expose_secret()).unwrap_u8() == 1
    }

    pub fn update_password(&mut self, new_password: SecretString) -> Result<()> {
        getrandom::fill(&mut self.salt)?;
        VaultFile::derive_secret(
            &new_password,
            &self.argon2,
            &self.salt,
            &mut self.secret.expose_secret_mut(),
        )?;

        self.save()
    }
}
