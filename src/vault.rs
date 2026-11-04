//! Authenticated encryption for findings in an explicitly enabled local vault.
use anyhow::{Context, Result, ensure};
use openssl::{
    pkcs5,
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use zeroize::Zeroizing;

pub const CHECK_AAD: &[u8] = b"cert-cracker vault verifier v1";
pub const CHECK_VALUE: &[u8] = b"cert-cracker vault unlock v1";
pub type Key = Zeroizing<[u8; 32]>;

pub fn derive(password: &[u8], salt: &[u8]) -> Result<Key> {
    ensure!(
        (12..=4096).contains(&password.len()),
        "vault password must contain 12..4096 bytes"
    );
    ensure!(salt.len() == 16, "invalid vault salt");
    let mut key = Zeroizing::new([0u8; 32]);
    pkcs5::scrypt(password, salt, 32768, 8, 1, 64 * 1024 * 1024, &mut key[..])
        .context("vault key derivation failed")?;
    Ok(key)
}
pub fn random_salt() -> Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    rand_bytes(&mut salt)?;
    Ok(salt)
}
pub fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    rand_bytes(&mut nonce)?;
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        aad,
        plaintext,
        &mut tag,
    )?;
    let mut result = Vec::with_capacity(28 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&tag);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}
pub fn open(key: &[u8], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        data.len() >= 28 && data.len() <= 1_048_576,
        "invalid encrypted finding length"
    );
    Ok(Zeroizing::new(
        decrypt_aead(
            Cipher::aes_256_gcm(),
            key,
            Some(&data[..12]),
            aad,
            &data[28..],
            &data[12..28],
        )
        .map_err(|_| anyhow::anyhow!("vault authentication failed"))?,
    ))
}
pub fn finding_aad(id: i64, target: &str) -> Vec<u8> {
    format!("cert-cracker finding v1\0{id}\0{target}").into_bytes()
}
