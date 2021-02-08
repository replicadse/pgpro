use pgp::types::KeyTrait;
use pgp::SignedSecretKey;
use pgp::SecretKeyParams;
use futures::executor::block_on;
use std::error::Error;
use std::result::Result;
use pgp::composed::{
    KeyType, SecretKey, SecretKeyParamsBuilder,
};
use pgp::composed::SubkeyParamsBuilder;
use pgp::crypto::{HashAlgorithm, SymmetricKeyAlgorithm};
use pgp::types::CompressionAlgorithm;
use smallvec::smallvec;

mod args;

async fn message() -> Result<(), Box<dyn Error>> {
    Ok(())
    // let mut decrypt_key_file = File::open("key.asc").unwrap();
    // let (decrypt_key, _headers) = SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap();
    // let message_file_path = "msg.asc";
    // let message_file = std::fs::read(message_file_path).unwrap();
    // let (message, _headers) = Message::from_armor_single(Cursor::new(message_file.clone())).unwrap();
    // message.decrypt(
    //     || "".to_string(),
    //     || "test".to_string(),
    //     &[&decrypt_key][..],
    // )?;
    // Ok(())
}

async fn main_async() -> Result<(), Box<dyn Error>> {
    let _cmd = args::ClapArgumentLoader::load().await?;

    let x: SignedSecretKey = generate().await?;
    store(&x).await?;
    list().await?;

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

async fn list() -> Result<(), Box<dyn Error>> {
    let tree = sled::open("./store")?;
    for e in tree.iter() {
        let v = e?;
        println!("{}", hex::encode(&v.0));
        println!("{}", String::from_utf8(v.1.to_vec())?);
    }
    Ok(())
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
