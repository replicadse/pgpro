use std::{
    cell::Cell,
    error::Error,
    io::Write,
    result::Result,
    sync::{
        Arc,
        Mutex,
    },
    thread,
    time::Duration,
};

use args::Command;
use db::{
    sled::SledDatabase,
    Database,
};
use futures::executor::block_on;
use pgp::{
    composed::{
        key::SecretKeyParamsBuilder,
        KeyType,
        SecretKey,
    },
    crypto::{
        HashAlgorithm,
        SymmetricKeyAlgorithm,
    },
    types::{
        CompressionAlgorithm,
        KeyTrait,
        SecretKeyTrait,
    },
    Deserializable,
    Message,
    SecretKeyParams,
    SignedSecretKey,
};
use smallvec::smallvec;

mod args;
mod db;
mod error;

async fn create_db() -> Result<Box<dyn Database>, Box<dyn Error>> {
    Ok(Box::new(SledDatabase::new("./store")))
}

async fn main_async() -> Result<(), Box<dyn Error>> {
    let cmd = args::ClapArgumentLoader::load().await?;
    match cmd.command {
        | Command::GenerateKey { owner, pass, .. } => {
            let gok = Arc::new(Mutex::new(Cell::new(false)));
            let gok_thread = gok.clone();
            print!("Generating key, this can take a while");
            std::io::stdout().flush().unwrap();
            let t = thread::spawn(move || loop {
                print!(".");
                std::io::stdout().flush().unwrap();
                if gok_thread.lock().unwrap().get() {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            });
            let x = generate(&owner, &pass).await?;
            create_db().await?.store(&x).await?;
            gok.lock().unwrap().set(true);
            t.join().unwrap();
            println!("{}", hex::encode(&x.fingerprint()).to_ascii_uppercase());
        },
        | Command::ListKeys => {
            fn print_key(k: &dyn KeyTrait, prefix: &str, context: &str) {
                print!("{}", prefix);
                print!("{}", hex::encode(k.fingerprint()).to_ascii_uppercase());
                print!(" ({})", hex::encode(k.key_id()).to_ascii_uppercase());
                let mut capabilities = Vec::<String>::new();
                if k.is_signing_key() {
                    capabilities.push("sign".to_owned());
                }
                if k.is_encryption_key() {
                    capabilities.push("encrypt".to_owned());
                }
                print!(" ({})", capabilities.join(", "));
                if !context.is_empty() {
                    print!(" ({})", context);
                }
                println!();
            }
            for k in create_db().await?.list().await? {
                print_key(&k, "", "secret, public");
                // print_key(&k.public_key(), "", "public");
                for subk in k.secret_subkeys.iter() {
                    print_key(subk, "\t", "secret sub");
                }
                for subk in k.public_subkeys.iter() {
                    print_key(subk, "\t", "public sub");
                }
            }
        },
        | Command::Encrypt { key, msg } => {
            let key = create_db().await?.read(&key).await?;
            let message = Message::new_literal("", &msg).compress(CompressionAlgorithm::ZLIB)?;
            let mut rng = rand::thread_rng();
            let msg_encrypted =
                message.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES256, &[&key.public_key()][..])?;
            let msg_encrypted_content = msg_encrypted.to_armored_bytes(None)?;
            let mut stdout = std::io::stdout();
            stdout.write_all(&msg_encrypted_content)?;
            stdout.flush()?;
        },
        | Command::Decrypt { key, pass, msg } => {
            let key = create_db().await?.read(&key).await?;
            let message = Message::from_string(&msg)?;
            let mut msg_decrypter = message.0.decrypt(|| "".to_owned(), || pass, &[&key])?;
            let msg_decrypted = msg_decrypter.0.next().unwrap()?.decompress()?;
            let msg_decrypted_content = msg_decrypted.get_content()?.unwrap();
            let mut stdout = std::io::stdout();
            stdout.write_all(&msg_decrypted_content)?;
            stdout.flush()?;
        },
    }
    Ok(())
}

async fn generate(user_id: &str, pass: &str) -> Result<SignedSecretKey, Box<dyn Error>> {
    let key_params: SecretKeyParams = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Rsa(4096))
        .can_create_certificates(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_512])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
        .passphrase(Some(pass.into()))
        .build()?;
    let k: SecretKey = key_params.generate()?;
    Ok(k.sign(|| String::from("test"))?)
}

fn main() -> Result<(), Box<dyn Error>> {
    block_on(main_async())
}
