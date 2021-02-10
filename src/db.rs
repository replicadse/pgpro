use std::{error::Error, io::Cursor};

use async_trait::async_trait;
use pgp::{Deserializable, SignedSecretKey, types::KeyTrait};

#[async_trait]
pub trait Database {
    async fn store(&self, key: &SignedSecretKey) -> Result<(), Box<dyn Error>>;
    async fn read(&self, fingerprint: &str) -> Result<SignedSecretKey, Box<dyn Error>>;
    async fn list(&self, ) -> Result<Vec<String>, Box<dyn Error>>;
}

pub struct SledDatabase {
    path: String,
}

impl SledDatabase {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_owned(),
        }
    }
}

#[async_trait]
impl Database for SledDatabase {
    async fn store(&self, key: &SignedSecretKey) -> Result<(), Box<dyn Error>> {
        let tree = sled::open(&self.path)?;
        tree.insert(key.fingerprint(), key.to_armored_string(None)?.as_bytes())?;
        tree.flush_async().await?;
        Ok(())
    }

    async fn read(&self, fingerprint: &str) -> Result<SignedSecretKey, Box<dyn Error>> {
        let tree = sled::open(&self.path)?;
        let v = tree.get(hex::decode(fingerprint)?)?
            .ok_or(crate::error::NotFoundError::new(fingerprint))?;
        let key = SignedSecretKey::from_armor_single(
            Cursor::new(v.to_vec()))?;
        Ok(key.0)
    }

    async fn list(&self, ) -> Result<Vec<String>, Box<dyn Error>> {
        let tree = sled::open(&self.path)?;
        let mut keys = std::vec::Vec::<String>::new();
        for e in tree.iter() {
            let v = e?;
            keys.push(hex::encode(&v.0));
        }
        Ok(keys)
    }
}