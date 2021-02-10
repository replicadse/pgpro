use args::Command;
use futures::executor::block_on;
use pgp::composed::SubkeyParamsBuilder;
use pgp::composed::{KeyType, SecretKey, SecretKeyParamsBuilder};
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::types::CompressionAlgorithm;
use pgp::SecretKeyParams;
use pgp::SignedSecretKey;
use pgp::{
    types::{KeyTrait, SecretKeyTrait},
    Deserializable, Message,
};
use smallvec::smallvec;
use std::result::Result;
use std::{error::Error, io::Write};

mod args;
mod db;
mod error;

use db::{Database, SledDatabase};

async fn create_db() -> Result<Box<dyn Database>, Box<dyn Error>> {
    Ok(Box::new(SledDatabase::new("./store")))
}

async fn main_async() -> Result<(), Box<dyn Error>> {
    let cmd = args::ClapArgumentLoader::load().await?;
    match cmd.command {
        Command::GenerateKey { .. } => {
            let x = generate().await?;
            create_db().await?.store(&x).await?;
            println!(
                "Key was created (fingerprint): {}",
                hex::encode(&x.fingerprint()).to_ascii_uppercase()
            );
        }
        Command::ListKeys => {
            for k in create_db().await?.list().await? {
                println!("Fingerprint: \t{}", hex::encode(k.fingerprint()));
                println!("ID: \t\t{}", hex::encode(k.key_id()));
                print!("Capabilities: \t");
                let mut capabilities = Vec::<String>::new();
                if k.is_signing_key() {
                    capabilities.push("sign".to_owned());
                }
                if k.is_encryption_key() {
                    capabilities.push("encrypt".to_owned());
                }
                println!("{}", capabilities.join(", "));
                println!();
            }
        }
        Command::Encrypt { key, msg } => {
            let key = create_db().await?.read(&key.unwrap()).await?;
            let message =
                Message::new_literal("", &msg.unwrap()).compress(CompressionAlgorithm::ZLIB)?;
            let mut rng = rand::thread_rng();
            let msg_encrypted = message.encrypt_to_keys(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                &[&key.public_key()][..],
            )?;
            let msg_encrypted_content = msg_encrypted.to_armored_bytes(None)?;
            let mut stdout = std::io::stdout();
            stdout.write_all(&msg_encrypted_content)?;
            stdout.flush()?;
        }
        Command::Decrypt { key, pass, msg } => {
            let key = create_db().await?.read(&key.unwrap()).await?;
            let message = Message::from_string(&msg.unwrap())?;
            let mut msg_decrypter =
                message
                    .0
                    .decrypt(|| "".to_owned(), || pass.unwrap(), &[&key])?;
            let msg_decrypted = msg_decrypter.0.next().unwrap()?.decompress()?;
            let msg_decrypted_content = msg_decrypted.get_content()?.unwrap();
            let mut stdout = std::io::stdout();
            stdout.write_all(&msg_decrypted_content)?;
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
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_512])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
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
    Ok(k.sign(|| String::from("test"))?)
}

fn main() -> Result<(), Box<dyn Error>> {
    block_on(main_async())
}
