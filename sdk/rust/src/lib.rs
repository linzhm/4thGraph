//! Construct and recognize canonical P2PKH-R1 raw scriptPubKeys.
use p256::PublicKey;
use regex::Regex;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const SIZE: usize = 59_582;
const START: usize = 208;
const END: usize = 228;
const FINGERPRINT: &str = "2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784";

pub fn recognize(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() != SIZE {
        return None;
    }
    static HEADER: OnceLock<Regex> = OnceLock::new();
    let pattern = HEADER.get_or_init(|| {
        Regex::new(r"^760052a569766b7c8201[0-9a-f]{396}([0-9a-f]{40})$").unwrap()
    });
    let header = hex::encode(&script[..END]);
    let capture = pattern.captures(&header)?;
    let mut hash = Sha256::new();
    hash.update(&script[..START]);
    hash.update(&script[END..]);
    if hex::encode(hash.finalize()) != FINGERPRINT {
        return None;
    }
    let mut owner = [0u8; 20];
    hex::decode_to_slice(&capture[1], &mut owner).ok()?;
    Some(owner)
}

pub fn lock_for_owner(template: &[u8], owner: &[u8; 20]) -> Result<Vec<u8>, &'static str> {
    recognize(template).ok_or("unrecognized P2PKH-R1 template")?;
    let mut script = template.to_vec();
    script[START..END].copy_from_slice(owner);
    Ok(script)
}

pub fn lock_for_key(template: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if key.len() != 65 || key[0] != 4 {
        return Err("expected uncompressed P-256 public key");
    }
    PublicKey::from_sec1_bytes(key).map_err(|_| "invalid P-256 point")?;
    let owner: [u8; 20] = Ripemd160::digest(Sha256::digest(key)).into();
    lock_for_owner(template, &owner)
}

pub mod payment;
