use std::error::Error;

use async_trait::async_trait;
use pgp::SignedSecretKey;

#[async_trait]
pub trait Database {
    async fn store(&self, key: &SignedSecretKey) -> Result<(), Box<dyn Error>>;
    async fn read(&self, fingerprint: &str) -> Result<SignedSecretKey, Box<dyn Error>>;
    async fn list(&self) -> Result<Vec<SignedSecretKey>, Box<dyn Error>>;
}

pub mod rustbreak {
    use std::{
        collections::HashMap,
        error::Error,
        io::Cursor,
    };

    use async_trait::async_trait;
    use pgp::{
        types::KeyTrait,
        Deserializable,
        SignedSecretKey,
    };

    use crate::db::Database;
    extern crate rustbreak;
    use rustbreak::{
        deser::Ron,
        FileDatabase,
    };

    pub struct RustbreakDatabase {
        db: FileDatabase<HashMap<String, String>, Ron>,
    }

    impl RustbreakDatabase {
        pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
            Ok(Self {
                db: FileDatabase::<HashMap<String, String>, Ron>::load_from_path_or_default(path)?,
            })
        }
    }

    #[async_trait]
    impl Database for RustbreakDatabase {
        async fn store(&self, key: &SignedSecretKey) -> Result<(), Box<dyn Error>> {
            let fp = hex::encode(key.fingerprint()).to_ascii_uppercase();
            let content = key.to_armored_string(None)?;
            self.db.write(|db| {
                db.insert(fp, content);
            })?;
            self.db.save()?;
            Ok(())
        }

        async fn read(&self, fingerprint: &str) -> Result<SignedSecretKey, Box<dyn Error>> {
            Ok(self.db.read(|db| {
                SignedSecretKey::from_armor_single(Cursor::new(db.get(fingerprint).unwrap().as_bytes()))
                    .unwrap()
                    .0
            })?)
        }

        async fn list(&self) -> Result<Vec<SignedSecretKey>, Box<dyn Error>> {
            Ok(self.db.read(|db| {
                let mut vals = Vec::<SignedSecretKey>::new();
                for (_, v) in db {
                    let key = SignedSecretKey::from_armor_single(Cursor::new(v.as_bytes())).unwrap().0;
                    vals.push(key);
                }
                vals
            })?)
        }
    }
}

pub mod keyring {
    use std::error::Error;

    use async_trait::async_trait;
    use pgp::SignedSecretKey;

    use crate::db::Database;
    extern crate keyring;
    use keyring::Keyring;

    pub struct KeyringDatabase {}

    impl KeyringDatabase {
        pub fn new() -> Self {
            Self {}
        }
    }

    #[async_trait]
    impl Database for KeyringDatabase {
        async fn store(&self, key: &SignedSecretKey) -> Result<(), Box<dyn Error>> {
            let kr = Keyring::new("pgpro", "username");
            kr.set_password("bananarama")?;
            Ok(())
        }

        async fn read(&self, fingerprint: &str) -> Result<SignedSecretKey, Box<dyn Error>> {
            unimplemented!()
        }

        async fn list(&self) -> Result<Vec<SignedSecretKey>, Box<dyn Error>> {
            unimplemented!()
        }
    }
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

    use crate::db::Database;

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
                .ok_or_else(|| crate::error::NotFoundError::new(fingerprint))?;
            let key = SignedSecretKey::from_armor_single(Cursor::new(v.to_vec()))?;
            Ok(key.0)
        }

        async fn list(&self) -> Result<Vec<SignedSecretKey>, Box<dyn Error>> {
            let tree = sled::open(&self.path)?;
            let mut keys = std::vec::Vec::<SignedSecretKey>::new();
            for e in tree.iter() {
                let v = e?;
                keys.push(SignedSecretKey::from_armor_single(Cursor::new(&v.1))?.0);
            }
            Ok(keys)
        }
    }
}
