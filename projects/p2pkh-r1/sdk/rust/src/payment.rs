use crate::recognize;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use p256::elliptic_curve::ops::Invert;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const MAX_AMOUNT: u64 = 2_100_000_000_000_000;

pub struct Output {
    pub satoshis: u64,
    pub script: Vec<u8>,
}

pub struct Payment {
    /// Funding transaction ID in display order.
    pub txid: [u8; 32],
    pub vout: u32,
    pub input_satoshis: u64,
    pub input_script: Vec<u8>,
    pub outputs: Vec<Output>,
    pub fee: u64,
}

fn hash256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

fn compact_size(n: usize, dst: &mut Vec<u8>) {
    match n {
        0..=252 => dst.push(n as u8),
        253..=65535 => { dst.push(253); dst.extend((n as u16).to_le_bytes()); }
        65536..=0xffff_ffff => { dst.push(254); dst.extend((n as u32).to_le_bytes()); }
        _ => { dst.push(255); dst.extend((n as u64).to_le_bytes()); }
    }
}

/// Create an ordinary one-input ForkID ALL payment from an authenticated UTXO.
pub fn sign_payment(
    p: &Payment,
    public_key: &[u8],
    sign_digest: impl FnOnce([u8; 32]) -> Result<[u8; 64], String>,
) -> Result<Vec<u8>, String> {
    if public_key.len() != 65 || public_key[0] != 4 {
        return Err("expected uncompressed P-256 key".into());
    }
    let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| "invalid P-256 public key")?;
    let owner: [u8; 20] = Ripemd160::digest(Sha256::digest(public_key)).into();
    if recognize(&p.input_script) != Some(owner) {
        return Err("wrong funding lock".into());
    }
    if p.input_satoshis > MAX_AMOUNT || p.outputs.is_empty() {
        return Err("invalid input amount or outputs".into());
    }
    let mut available = p.input_satoshis.checked_sub(p.fee).ok_or("fee exceeds input amount")?;
    let mut outputs = Vec::new();
    for output in &p.outputs {
        available = available.checked_sub(output.satoshis).ok_or("output exceeds available funds")?;
        outputs.extend(output.satoshis.to_le_bytes());
        compact_size(output.script.len(), &mut outputs);
        outputs.extend_from_slice(&output.script);
    }
    if available != 0 {
        return Err("payment does not balance".into());
    }

    let version = 2u32.to_le_bytes();
    let sequence = u32::MAX.to_le_bytes();
    let locktime = 0u32.to_le_bytes();
    let mut outpoint = p.txid.to_vec();
    outpoint.reverse();
    outpoint.extend(p.vout.to_le_bytes());
    let mut pre = Vec::with_capacity(159);
    pre.extend(version);
    pre.extend(hash256(&outpoint));
    pre.extend(hash256(&sequence));
    pre.extend(&outpoint);
    pre.extend([2, 0x68, 0xac]);
    pre.extend(p.input_satoshis.to_le_bytes());
    pre.extend(sequence);
    pre.extend(hash256(&outputs));
    pre.extend(locktime);
    pre.extend(0x41u32.to_le_bytes());

    let digest = hash256(&pre);
    let raw = sign_digest(digest)?;
    let sig = Signature::from_slice(&raw).map_err(|_| "invalid R1 scalars")?;
    key.verify_prehash(&digest, &sig).map_err(|_| "invalid R1 digest signature")?;
    let mut inverse = sig.s().invert().to_bytes().to_vec();
    inverse.reverse();
    let mut witness = vec![0x4c, pre.len() as u8];
    witness.extend(pre);
    witness.push(65);
    witness.extend(public_key);
    witness.push(64);
    witness.extend(raw);
    witness.push(32);
    witness.extend(inverse);
    witness.push(0);
    let mut tx = version.to_vec();
    tx.push(1);
    tx.extend(outpoint);
    compact_size(witness.len(), &mut tx);
    tx.extend(witness);
    tx.extend(sequence);
    compact_size(p.outputs.len(), &mut tx);
    tx.extend(outputs);
    tx.extend(locktime);
    Ok(tx)
}
