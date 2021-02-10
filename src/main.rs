use args::Command;
use pgp::{Deserializable, Message, PublicKey, types::{KeyTrait, SecretKeyTrait}};
use pgp::SignedSecretKey;
use pgp::SecretKeyParams;
use futures::executor::block_on;
use std::{error::Error, io::{Cursor, Write}};
use std::result::Result;
use pgp::composed::{
    KeyType, SecretKey, SecretKeyParamsBuilder,
};
use pgp::composed::SubkeyParamsBuilder;
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::types::CompressionAlgorithm;
use smallvec::smallvec;

mod args;
mod error;

async fn message(key: &PublicKey) -> Result<String, Box<dyn Error>> {
    let msg = Message::new_literal("", "hi").compress(CompressionAlgorithm::ZLIB)?;
    let mut rng = rand::thread_rng();
    let msgenc = msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES256, &[&key][..])?;
    let msgstr = msgenc.to_armored_string(None)?;
    println!("{}", &msgstr);
    Ok(msgstr)
}

async fn message2(msg: &str, key: &SignedSecretKey) -> Result<String, Box<dyn Error>> {
    let msg_t = Message::from_string(msg)?;
    let mut msg_d = msg_t.0.decrypt(
        || "".to_owned(), 
        || "test".to_owned(), 
        &[key])?;
    let mut msg_dec = msg_d.0.next().unwrap()?;
    msg_dec = msg_dec.decompress()?;
    Ok(String::from_utf8(msg_dec.get_content()?.unwrap())?)
}

async fn main_async() -> Result<(), Box<dyn Error>> {
    let cmd = args::ClapArgumentLoader::load().await?;
    match cmd.command {
        Command::GenerateKey {..} => {
            let x = generate().await?;
            store(&x).await?;
            println!("Key was created (fingerprint): {}", hex::encode(&x.fingerprint()));
        }
        Command::ListKeys => {
            for k in list().await? {
                println!("{}", k);
            }
        }
        Command::Encrypt {
            key, msg,
        } => {
            let key = get(&key.unwrap()).await?;
            let msg = Message::new_literal("", &msg.unwrap())
                .compress(CompressionAlgorithm::ZLIB)?;
            let mut rng = rand::thread_rng();
            let msgenc = msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES256, &[&key.public_key()][..])?;
            let msgstr = msgenc.to_armored_string(None)?;
            let mut stdout = std::io::stdout();
            stdout.write_all(&msgstr.as_bytes())?;
            stdout.flush()?;
        }
        Command::Decrypt {
            key, pass, msg,
        } => {
            let key = get(&key.unwrap()).await?;
            let msg_t = Message::from_string(&msg.unwrap())?;
            let mut msg_d = msg_t.0.decrypt(
                || "".to_owned(), 
                || pass.unwrap(), 
                &[&key])?;
            let mut msg_dec = msg_d.0.next().unwrap()?;
            msg_dec = msg_dec.decompress()?;
            let mut stdout = std::io::stdout();
            stdout.write_all(&msg_dec.get_content()?.unwrap())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

async fn generate() -> Result<SignedSecretKey, Box<dyn Error>> {
    let key_params: SecretKeyParams = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Rsa(2048))
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id("Me <me@mail.com>".into())
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
        ])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_512,
        ])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
        ])
        .passphrase(Some("test".to_string()))
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::Rsa(4096))
                .passphrase(None)
                .can_encrypt(true)
                .build()
                .unwrap(),
        )
        .build()?;
    let k: SecretKey = key_params.generate()?;
    Ok(k.sign(|| { String::from("test") })?)
}

async fn list() -> Result<Vec<String>, Box<dyn Error>> {
    let tree = sled::open("./store")?;
    let mut keys = std::vec::Vec::<String>::new();
    for e in tree.iter() {
        let v = e?;
        keys.push(hex::encode(&v.0));
    }
    Ok(keys)
}

async fn get(fp: &str) -> Result<SignedSecretKey, Box<dyn Error>> {
    let tree = sled::open("./store")?;
    let v = tree.get(hex::decode(fp)?)?
        .ok_or(crate::error::NotFoundError::new(fp))?;
    let key = SignedSecretKey::from_armor_single(
        Cursor::new(v.to_vec()))?;
    Ok(key.0)
}

async fn store(key: &SignedSecretKey) -> Result<(), Box<dyn Error>> {
    let tree = sled::open("./store")?;
    tree.insert(key.fingerprint(), key.to_armored_string(None)?.as_bytes())?;
    tree.flush_async().await?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    block_on(main_async())
}
