use std::error::Error;

use async_trait::async_trait;
use pgp::SignedSecretKey;

#[async_trait]
pub trait Database {
    async fn store(&self, key: &SignedSecretKey) -> Result<(), Box<dyn Error>>;
    async fn read(&self, fingerprint: &str) -> Result<SignedSecretKey, Box<dyn Error>>;
    async fn list(&self) -> Result<Vec<SignedSecretKey>, Box<dyn Error>>;
}

pub mod sled {
    use std::{
        error::Error,
        io::Cursor,
    };

    use async_trait::async_trait;
    use pgp::{
        types::KeyTrait,
        Deserializable,
        SignedSecretKey,
    };

    use crate::{
        db::Database,
        error::NotFoundError,
    };

    pub struct SledDatabase {
        path: String,
    }

    impl SledDatabase {
        pub fn new(path: &str) -> Self {
            Self { path: path.to_owned() }
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
            let v = tree
                .get(hex::decode(fingerprint)?)?
                .ok_or_else(|| NotFoundError::new(fingerprint))?;
            let key = SignedSecretKey::from_armor_single(Cursor::new(v.to_vec()))?;
            Ok(key.0)
        }

        async fn list(&self) -> Result<Vec<SignedSecretKey>, Box<dyn Error>> {
            let tree = sled::open(&self.path)?;
            let mut keys = Vec::<SignedSecretKey>::new();
            for e in tree.iter() {
                let v = e?;
                keys.push(SignedSecretKey::from_armor_single(Cursor::new(&v.1))?.0);
            }
            Ok(keys)
        }
    }
}
