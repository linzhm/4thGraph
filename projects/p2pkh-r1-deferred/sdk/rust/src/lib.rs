//! Construct and recognize canonical P2PKH-R1-Deferred raw scriptPubKeys.
use sha2::{Digest, Sha256};

const FIELDS: [(usize, usize); 4] = [(1, 21), (22, 54), (109, 117), (134, 166)];
const FINGERPRINT: [u8; 32] = [
    0xc8, 0x1b, 0x70, 0xf5, 0x9e, 0x00, 0x40, 0x2f, 0xb3, 0xcd, 0x93, 0x6d, 0x17, 0x4e, 0x7c, 0x8a,
    0x45, 0xeb, 0x82, 0x05, 0xa1, 0x8b, 0x3a, 0xd4, 0x3f, 0xac, 0x29, 0xe9, 0x3f, 0x58, 0xcc, 0xb4,
];

#[derive(Debug, PartialEq, Eq)]
pub struct Commitment {
    pub owner_hash160: [u8; 20],
    pub public_key: Option<[u8; 65]>,
    pub target_script_sha256: [u8; 32],
    pub target_txout_hash256: [u8; 32],
}

fn canonical(script: &[u8]) -> bool {
    let Ok(mut fixed) = <[u8; 1435]>::try_from(script) else {
        return false;
    };
    for (start, end) in FIELDS {
        fixed[start..end].fill(0);
    }
    Sha256::digest(fixed)[..] == FINGERPRINT
}

fn is_legacy(script: &[u8]) -> bool {
    script.len() == 1480 && script.starts_with(&[65, 4])
}

fn compact_template(template: &[u8], owner: &[u8; 20]) -> Vec<u8> {
    if is_legacy(template) {
        let mut script = Vec::with_capacity(1435);
        script.push(20);
        script.extend_from_slice(owner);
        script.extend_from_slice(&template[66..]);
        return script;
    }
    template.to_vec()
}

fn build_lock(
    template: &[u8],
    target: &[u8],
    owner: &[u8; 20],
    satoshis: u64,
) -> Result<Vec<u8>, &'static str> {
    let mut script = compact_template(template, owner);
    if !canonical(&script) {
        return Err("unrecognized deferred template");
    }
    if satoshis > 2_100_000_000_000_000 {
        return Err("invalid amount");
    }
    let mut output_hash = Sha256::new();
    output_hash.update(satoshis.to_le_bytes());
    output_hash.update([0xfd]);
    output_hash.update((target.len() as u16).to_le_bytes());
    output_hash.update(target);
    let output_hash = Sha256::digest(output_hash.finalize());
    if output_hash[..] == [0; 32] {
        return Err("zero target commitment");
    }
    script[1..21].copy_from_slice(owner);
    script[22..54].copy_from_slice(&Sha256::digest(target));
    script[109..117].copy_from_slice(&satoshis.to_le_bytes());
    script[134..166].copy_from_slice(&output_hash);
    Ok(script)
}

pub fn lock_for_owner(
    template: &[u8],
    r1_template: &[u8],
    owner: &[u8; 20],
    satoshis: u64,
) -> Result<Vec<u8>, &'static str> {
    let target = p2pkh_r1::lock_for_owner(r1_template, owner)?;
    build_lock(template, &target, owner, satoshis)
}

pub fn lock_for_key(
    template: &[u8],
    r1_template: &[u8],
    public_key: &[u8],
    satoshis: u64,
) -> Result<Vec<u8>, &'static str> {
    let target = p2pkh_r1::lock_for_key(r1_template, public_key)?;
    let owner = p2pkh_r1::recognize(&target).ok_or("unrecognized target R1 lock")?;
    build_lock(template, &target, &owner, satoshis)
}

pub fn recognize(r1_template: &[u8], script: &[u8], satoshis: u64) -> Option<Commitment> {
    let (owner_hash160, public_key) = if is_legacy(script) {
        let key: [u8; 65] = script[1..66].try_into().ok()?;
        let target = p2pkh_r1::lock_for_key(r1_template, &key).ok()?;
        (p2pkh_r1::recognize(&target)?, Some(key))
    } else {
        (script.get(1..21)?.try_into().ok()?, None)
    };
    let compact = compact_template(script, &owner_hash160);
    if lock_for_owner(&compact, r1_template, &owner_hash160, satoshis).ok()? != compact {
        return None;
    }
    Some(Commitment {
        owner_hash160,
        public_key,
        target_script_sha256: compact[22..54].try_into().ok()?,
        target_txout_hash256: compact[134..166].try_into().ok()?,
    })
}

/// Encode a direct ForkID SINGLE activation.
pub fn activation_witness(
    r1_template: &[u8],
    script: &[u8],
    satoshis: u64,
    preimage: &[u8],
) -> Result<Vec<u8>, &'static str> {
    activation_witness_with_digest(r1_template, script, satoshis, preimage, None)
}

/// Encode the output-check preimage and optional type byte plus selected digest.
pub fn activation_witness_with_digest(
    r1_template: &[u8],
    script: &[u8],
    satoshis: u64,
    preimage: &[u8],
    auxiliary: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    let commitment = recognize(r1_template, script, satoshis).ok_or("wrong funding lock")?;
    let code: &[u8] = if auxiliary.is_some() {
        &[4, 0xad, 0x68, 0xab, 0xac]
    } else {
        &[1, 0xac]
    };
    let value_offset = 104 + code.len();
    if preimage.len() != value_offset + 52
        || &preimage[104..value_offset] != code
        || preimage[value_offset..value_offset + 8] != satoshis.to_le_bytes()
        || preimage[value_offset + 12..value_offset + 44] != commitment.target_txout_hash256
    {
        return Err("activation preimage does not match the funding output");
    }
    let binding_type = u32::from_le_bytes(preimage[preimage.len() - 4..].try_into().unwrap());
    if !matches!(binding_type, 0x43 | 0xc3) {
        return Err("expected ForkID SINGLE");
    }
    let mut witness = Vec::new();
    if let Some(extra) = auxiliary {
        let [mode, ..] =
            <[u8; 33]>::try_from(extra).map_err(|_| "invalid auxiliary activation digest")?;
        if !matches!(mode & 0x5f, 0x41..=0x43)
            || matches!(mode, 0x43 | 0xc3)
            || u32::from(mode & 0x80) != binding_type & 0x80
        {
            return Err("invalid auxiliary activation type");
        }
        witness.push(33);
        witness.extend_from_slice(extra);
    }
    witness.extend_from_slice(&[0x4c, preimage.len() as u8]);
    witness.extend_from_slice(preimage);
    Ok(witness)
}
