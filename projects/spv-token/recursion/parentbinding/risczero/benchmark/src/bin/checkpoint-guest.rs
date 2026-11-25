#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Block, Digest, Impl, Sha256, BLOCK_BYTES, SHA256_INIT};

risc0_zkvm::guest::entry!(main);

const PARENT_BYTES: usize = 3433;
const PROCESSED_BYTES: usize = 1856;
const OUTPUT_COUNT_OFFSET: usize = 1871;
const SUFFIX_BYTES: usize = PARENT_BYTES - PROCESSED_BYTES;

fn double_sha256(bytes: &[u8]) -> Digest {
    *Impl::hash_bytes(Impl::hash_bytes(bytes).as_bytes())
}

fn compress_blocks(state: &Digest, bytes: &[u8]) -> Digest {
    assert_eq!(bytes.len() % BLOCK_BYTES, 0);
    let blocks: Vec<_> = bytes
        .chunks_exact(BLOCK_BYTES)
        .map(|block| Block::try_from(block).unwrap())
        .collect();
    *Impl::compress_slice(state, &blocks)
}

fn main() {
    let mut parent = [0u8; PARENT_BYTES];
    env::read_slice(&mut parent);
    // Mirror parentcheckpoint.TokenCircuit, including its fixed CompactSizes.
    assert_eq!(parent[4], 2);
    assert_eq!(&parent[41..44], &[0xfd, 0xf6, 0x06]);
    assert_eq!(parent[OUTPUT_COUNT_OFFSET - 5], 0);
    assert_eq!(parent[OUTPUT_COUNT_OFFSET], 1);
    let output = OUTPUT_COUNT_OFFSET + 1;
    let satoshis = u64::from_le_bytes(parent[output..output + 8].try_into().unwrap());
    assert!((1..=2_100_000_000_000_000).contains(&satoshis));
    assert_eq!(&parent[output + 8..output + 11], &[0xfd, 0x0a, 0x06]);
    let marker = b"\x12BSV/CCTP/token/v2\0\x4a";
    let script = output + 11;
    assert_eq!(&parent[script..script + marker.len()], marker);
    let quantity = script + marker.len() + 32;
    assert_ne!(&parent[quantity..quantity + 8], &[0; 8]);
    let owner = quantity + 8;
    assert!(matches!(parent[owner], 2 | 3));
    assert_eq!(parent[owner + 33], 0);

    let midstate = compress_blocks(&SHA256_INIT, &parent[..PROCESSED_BYTES]);
    let suffix = &parent[PROCESSED_BYTES..];
    const PADDED_SUFFIX_BYTES: usize = (SUFFIX_BYTES + 9).next_multiple_of(BLOCK_BYTES);
    let mut padded_suffix = [0u8; PADDED_SUFFIX_BYTES];
    padded_suffix[..SUFFIX_BYTES].copy_from_slice(suffix);
    padded_suffix[SUFFIX_BYTES] = 0x80;
    padded_suffix[PADDED_SUFFIX_BYTES - 8..]
        .copy_from_slice(&((PARENT_BYTES as u64) * 8).to_be_bytes());
    let inner = compress_blocks(&midstate, &padded_suffix);
    let txid = Impl::hash_bytes(inner.as_bytes());

    let mut statement = b"BSV/CCTP/parent-checkpoint/v1\0".to_vec();
    statement.extend_from_slice(txid.as_bytes());
    statement.extend_from_slice(midstate.as_bytes());
    statement.extend_from_slice(&(PROCESSED_BYTES as u64).to_le_bytes());
    statement.extend_from_slice(&(OUTPUT_COUNT_OFFSET as u32).to_le_bytes());
    statement.extend_from_slice(&1u32.to_le_bytes());
    statement.extend_from_slice(double_sha256(suffix).as_bytes());
    statement.extend_from_slice(&[0; 32]);
    env::commit_slice(double_sha256(&statement).as_bytes());
}
