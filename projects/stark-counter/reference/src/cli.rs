use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use winterfell::{crypto::ElementHasher, math::fields::f128::BaseElement};

use crate::{counter, opening};

const MAX_PROOF_BYTES: u64 = 1 << 20;

fn read_proof(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_PROOF_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROOF_BYTES {
        return Err("proof exceeds the reference byte limit".into());
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run<H: ElementHasher<BaseField = BaseElement> + Sync>(
    binary: &str,
    args: &[String],
) -> Result<(), Box<dyn Error>> {
    match args {
        [command, current, path] if command == "prove" => {
            let current = current.parse::<u32>()?;
            let (next, proof) = counter::prove::<H>(current)?;
            fs::write(path, proof)?;
            println!("{next}");
        }
        [command, current, next, path] if command == "verify" => {
            let proof = read_proof(Path::new(path))?;
            counter::verify::<H>(current.parse::<u32>()?, next.parse::<u32>()?, &proof)?;
        }
        [command, current, next, query, path] if command == "trace-opening" => {
            let proof = read_proof(Path::new(path))?;
            let opening = opening::trace_opening::<H>(
                current.parse()?,
                next.parse()?,
                query.parse()?,
                &proof,
            )?;
            println!(
                r#"{{"index":{},"root":"{}","row":"{}","path":"{}"}}"#,
                opening.index,
                hex(&opening.root),
                hex(&opening.row),
                hex(&opening.path),
            );
        }
        _ => {
            return Err(
                format!("usage: {binary} prove CURRENT PROOF | verify CURRENT NEXT PROOF | trace-opening CURRENT NEXT QUERY PROOF").into(),
            );
        }
    }
    Ok(())
}

pub fn run_cli<H: ElementHasher<BaseField = BaseElement> + Sync>(binary: &str) {
    let args: Vec<_> = env::args().skip(1).collect();
    if let Err(error) = run::<H>(binary, &args) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
