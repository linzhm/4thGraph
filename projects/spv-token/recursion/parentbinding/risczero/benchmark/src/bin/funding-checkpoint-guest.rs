#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Block, Digest, Impl, Sha256, BLOCK_BYTES, SHA256_INIT};

risc0_zkvm::guest::entry!(main);

const DOMAIN: &[u8] = b"BSV/CCTP/verifier-funding-checkpoint/v1\0";
const MAX_BYTES: usize = 1_000_000;
const MAX_MONEY: u64 = 2_100_000_000_000_000;

fn compact_size(raw: &[u8], offset: usize) -> (usize, usize) {
    let lead = raw[offset];
    let start = offset + 1;
    let (value, width, minimum) = match lead {
        0..=252 => return (lead as usize, start),
        253 => (
            u16::from_le_bytes(raw[start..start + 2].try_into().unwrap()) as u32,
            2,
            253,
        ),
        254 => (
            u32::from_le_bytes(raw[start..start + 4].try_into().unwrap()),
            4,
            65_536,
        ),
        255 => panic!("funding transaction exceeds the profile"),
    };
    assert!(value >= minimum);
    (value as usize, start + width)
}

fn hash256(bytes: &[u8]) -> Digest {
    *Impl::hash_bytes(Impl::hash_bytes(bytes).as_bytes())
}

fn compress(state: &Digest, bytes: &[u8]) -> Digest {
    assert_eq!(bytes.len() % BLOCK_BYTES, 0);
    let blocks: Vec<_> = bytes
        .chunks_exact(BLOCK_BYTES)
        .map(|block| Block::try_from(block).unwrap())
        .collect();
    *Impl::compress_slice(state, &blocks)
}

fn main() {
    let mut length_field = [0u8; 4];
    env::read_slice(&mut length_field);
    let length = u32::from_le_bytes(length_field) as usize;
    assert!((60..=MAX_BYTES).contains(&length));
    let mut raw = vec![0u8; length];
    env::read_slice(&mut raw);

    // The funding profile has one input and exactly one output at vout 0.
    assert_eq!(raw[4], 1);
    let (witness_len, witness_start) = compact_size(&raw, 41);
    assert!(witness_len < 253);
    let count_offset = witness_start + witness_len + 4;
    assert_eq!(raw[count_offset], 1);
    let output = count_offset + 1;
    let value = u64::from_le_bytes(raw[output..output + 8].try_into().unwrap());
    assert!((1..=MAX_MONEY).contains(&value));
    let script_field = output + 8;
    let (script_len, script_start) = compact_size(&raw, script_field);
    assert!((1..=MAX_BYTES).contains(&script_len));
    assert_eq!(script_start + script_len + 4, length);
    let lock_hash = Impl::hash_bytes(&raw[script_field..length - 4]);

    let processed = length - length % BLOCK_BYTES;
    let state = compress(&SHA256_INIT, &raw[..processed]);
    let suffix = &raw[processed..];
    let mut padded = [0u8; 2 * BLOCK_BYTES];
    let padded_len = (suffix.len() + 9).next_multiple_of(BLOCK_BYTES);
    padded[..suffix.len()].copy_from_slice(suffix);
    padded[suffix.len()] = 0x80;
    padded[padded_len - 8..padded_len].copy_from_slice(&((length as u64) * 8).to_be_bytes());
    let inner = compress(&state, &padded[..padded_len]);
    let txid = Impl::hash_bytes(inner.as_bytes());

    let mut statement = DOMAIN.to_vec();
    statement.extend_from_slice(txid.as_bytes());
    statement.extend_from_slice(&0u32.to_le_bytes());
    statement.extend_from_slice(lock_hash.as_bytes());
    statement.extend_from_slice(&value.to_le_bytes());
    statement.extend_from_slice(&(count_offset as u32).to_le_bytes());
    statement.extend_from_slice(&length_field);
    statement.extend_from_slice(&(processed as u32).to_le_bytes());
    statement.extend_from_slice(state.as_bytes());
    statement.extend_from_slice(hash256(suffix).as_bytes());
    env::commit_slice(hash256(&statement).as_bytes());
}
