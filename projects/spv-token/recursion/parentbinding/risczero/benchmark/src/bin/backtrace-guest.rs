#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Digest, Impl, Sha256};

risc0_zkvm::guest::entry!(main);

const TEMPLATE_HEX: &str =
    include_str!("../../../../../parentcheckpoint/backtrace-token-template.hex");
const DOMAIN: &[u8] = b"BSV/CCTP/parent-openings/v1\0";
const TOKEN_BYTES: usize = 769;
const QUANTITY: std::ops::Range<usize> = 30..38;
const OWNER: std::ops::Range<usize> = 56..89;
const FUNDING: std::ops::Range<usize> = 147..179;

fn sha256d(bytes: &[u8]) -> Digest {
    *Impl::hash_bytes(Impl::hash_bytes(bytes).as_bytes())
}

fn expect(raw: &[u8], cursor: &mut usize, bytes: &[u8]) {
    let end = *cursor + bytes.len();
    assert_eq!(&raw[*cursor..end], bytes);
    *cursor = end;
}

fn open_parent(
    raw: &[u8],
    layout: u8,
    vout: u32,
    funding: &[u8; 32],
    template: &[u8; TOKEN_BYTES],
) -> (Digest, Vec<u8>) {
    let (lengths, count): (&[usize], u8) = match layout {
        0 => (&[72], 1),
        1 => (&[1624, 376, 376], 2),
        _ => panic!("unsupported parent layout"),
    };
    assert!(vout < u32::from(count));
    let mut cursor = 4;
    expect(raw, &mut cursor, &[lengths.len() as u8]);
    let source = &raw[cursor..cursor + 36];
    for &length in lengths {
        cursor += 36;
        if length < 253 {
            expect(raw, &mut cursor, &[length as u8]);
        } else {
            expect(raw, &mut cursor, &[253]);
            expect(raw, &mut cursor, &(length as u16).to_le_bytes());
        }
        cursor += length + 4;
    }
    expect(raw, &mut cursor, &[count]);
    let mut selected = &[][..];
    for position in 0..u32::from(count) {
        let satoshis = u64::from_le_bytes(raw[cursor..cursor + 8].try_into().unwrap());
        assert!(satoshis <= 2_100_000_000_000_000);
        cursor += 8;
        expect(raw, &mut cursor, &[253]);
        expect(raw, &mut cursor, &(TOKEN_BYTES as u16).to_le_bytes());
        if position == vout {
            assert_eq!(satoshis, 1_000);
            selected = &raw[cursor..cursor + TOKEN_BYTES];
        }
        cursor += TOKEN_BYTES;
    }
    assert_eq!(cursor + 4, raw.len());
    for (i, (&actual, &constant)) in selected.iter().zip(template).enumerate() {
        if FUNDING.contains(&i) {
            assert_eq!(actual, funding[i - FUNDING.start]);
        } else if !QUANTITY.contains(&i) && !OWNER.contains(&i) {
            assert_eq!(actual, constant);
        }
    }
    let mut claim = vec![layout];
    claim.extend_from_slice(source);
    claim.extend_from_slice(&selected[QUANTITY]);
    claim.extend_from_slice(&selected[OWNER]);
    (sha256d(raw), claim)
}

fn main() {
    let mut funding = [0u8; 32];
    env::read_slice(&mut funding);
    let mut template = [0u8; TOKEN_BYTES];
    let ascii = TEMPLATE_HEX.trim().as_bytes();
    assert_eq!(ascii.len(), 2 * TOKEN_BYTES);
    for (i, byte) in template.iter_mut().enumerate() {
        let high = (ascii[2 * i] as char).to_digit(16).unwrap() as u8;
        let low = (ascii[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        *byte = high * 16 + low;
    }
    let mut statement = DOMAIN.to_vec();
    statement.extend_from_slice(&funding);
    let mut claims = Vec::with_capacity(156);
    for _ in 0..2 {
        let mut descriptor = [0u8; 5];
        env::read_slice(&mut descriptor);
        let layout = descriptor[0];
        let mut raw = vec![
            0u8;
            match layout {
                0 => 903,
                1 => 4075,
                _ => panic!("unsupported parent layout"),
            }
        ];
        env::read_slice(&mut raw);
        let vout = u32::from_le_bytes(descriptor[1..].try_into().unwrap());
        let (txid, claim) = open_parent(&raw, layout, vout, &funding, &template);
        statement.extend_from_slice(txid.as_bytes());
        statement.extend_from_slice(&descriptor[1..]);
        claims.extend_from_slice(&claim);
    }
    statement.extend_from_slice(&claims);
    env::commit_slice(sha256d(&statement).as_bytes());
}
