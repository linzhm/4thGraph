use std::env;
use std::fs;
use std::time::Instant;

use bincode::Options;
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let [receipt_path, image_id, expected_digest]: [String; 3] = env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "usage: checkpoint-verify RECEIPT IMAGE_ID EXPECTED_DIGEST")?;
    let image_id = Digest::try_from(hex::decode(image_id)?.as_slice())?;
    let expected_digest = hex::decode(expected_digest)?;
    let raw = fs::read(receipt_path)?;
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&raw)?;
    let kind = match &receipt.inner {
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Succinct(_) => "succinct",
        _ => return Err("expected a cryptographic STARK receipt".into()),
    };
    let started = Instant::now();
    receipt.verify(image_id)?;
    if receipt.journal.bytes != expected_digest || expected_digest.len() != 32 {
        return Err("receipt proves a different checkpoint digest".into());
    }
    println!(
        "kind={kind} receipt_bytes={} native_verify_seconds={:.6}",
        raw.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
