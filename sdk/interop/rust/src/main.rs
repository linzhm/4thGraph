use bsv_rs::primitives::bsv::sighash::TxOutput;
use bsv_rs::script::{Spend, SpendParams};
use bsv_rs::transaction::Transaction;
use serde::Deserialize;
use std::{env, error::Error, fs};

#[derive(Deserialize)]
struct Payment {
    funding: String,
    signed: String,
    txid: String,
    #[serde(default)]
    vout: u32,
}

#[derive(Deserialize)]
struct ProjectPayment {
    project: String,
    release: String,
    #[serde(flatten)]
    payment: Payment,
}

fn decode_payment(fixture: &Payment) -> Result<(Transaction, Transaction), Box<dyn Error>> {
    let funding = Transaction::from_hex(&fixture.funding)?;
    let signed = Transaction::from_hex(&fixture.signed)?;
    if funding.to_hex() != fixture.funding
        || signed.to_hex() != fixture.signed
        || signed.id() != fixture.txid
    {
        return Err("transaction did not round-trip".into());
    }
    let [input] = signed.inputs.as_slice() else {
        return Err("expected one spending input".into());
    };
    if input.get_source_txid_bytes()? != funding.hash()
        || input.source_output_index != fixture.vout
        || funding.outputs.get(fixture.vout as usize).is_none()
    {
        return Err("payment does not spend the funding outpoint".into());
    }
    Ok((funding, signed))
}

fn verify_native(fixture: &Payment) -> Result<(), Box<dyn Error>> {
    let (funding, signed) = decode_payment(fixture)?;
    let input = &signed.inputs[0];
    let output = &funding.outputs[fixture.vout as usize];
    let mut spend = Spend::new(SpendParams {
        source_txid: funding.hash(),
        source_output_index: input.source_output_index,
        source_satoshis: output.satoshis.ok_or("missing funding amount")?,
        locking_script: output.locking_script.clone(),
        transaction_version: signed.version as i32,
        other_inputs: Vec::new(),
        outputs: signed
            .outputs
            .iter()
            .map(|output| {
                Ok(TxOutput {
                    satoshis: output.satoshis.ok_or("missing payment amount")?,
                    script: output.locking_script.to_binary(),
                })
            })
            .collect::<Result<_, &str>>()?,
        input_index: 0,
        unlocking_script: input.unlocking_script.clone().ok_or("missing unlock")?,
        input_sequence: input.sequence,
        lock_time: signed.lock_time,
        memory_limit: None,
        work_limit: None,
    });
    if !spend.validate()? {
        return Err("Rust BSV SDK rejected the spending script".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let native_path = args.next().ok_or("expected a BRC-29 fixture path")?;
    let projects_path = args.next().ok_or("expected a project fixture path")?;
    let native: Payment = serde_json::from_slice(&fs::read(native_path)?)?;
    verify_native(&native)?;
    println!("Rust SDK: {}", native.txid);

    let projects: Vec<ProjectPayment> = serde_json::from_slice(&fs::read(projects_path)?)?;
    for row in &projects {
        decode_payment(&row.payment)
            .map_err(|err| format!("{} v{}: {}", row.project, row.release, err))?;
    }
    println!(
        "Rust SDK: {} project transactions round-tripped",
        projects.len()
    );
    Ok(())
}
