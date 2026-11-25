use bsv_script_lab_local_sdk::{
    Activation, Config, LockRequest, RecognizeRequest, SigningRequest, WalletClient, WalletInput,
    WalletPayment, WalletRecognition,
};
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf};

#[test]
fn replay() {
    let Ok(path) = env::var("SCRIPT_LAB_SDK_VECTOR") else {
        eprintln!("run shared/sdk/verify_wallet.sh PROJECT to replay the unified SDK vectors");
        return;
    };
    let source = fs::read(path).unwrap();
    let rows: Vec<Value> = serde_json::from_slice(&source).unwrap();
    assert!(!rows.is_empty());
    let project = env::var("SCRIPT_LAB_SDK_PROJECT").unwrap().leak();
    for row in rows {
        let field = |name: &str| row[name].as_str().unwrap();
        let client = WalletClient::new(
            project,
            Config {
                python: PathBuf::from(env::var("SCRIPT_LAB_SDK_PYTHON").unwrap()),
                bridge: PathBuf::from(env::var("SCRIPT_LAB_SDK_BRIDGE").unwrap()),
            },
            Some(field("profile").into()),
        );
        let prevout = client
            .prevout_from_funding(field("funding"), row["vout"].as_u64().unwrap() as u32)
            .unwrap();
        assert_eq!(
            serde_json::to_value(&prevout).unwrap(),
            row["request"]["prevout"]
        );
        let input: WalletInput = serde_json::from_value(row["request"].clone()).unwrap();
        let value_sats = row["signature"]
            .is_null()
            .then(|| prevout.output.value_sats.clone());
        let pubkey = Some(input.options.public_key.clone());
        let lock = field("lock").to_owned();
        let expected: WalletRecognition =
            serde_json::from_value(row["recognition"].clone()).unwrap();
        if row["existingOutput"] != true {
            assert_eq!(
                client
                    .create_lock(LockRequest {
                        public_key: pubkey.clone(),
                        value_sats: value_sats.clone(),
                        ..Default::default()
                    })
                    .unwrap(),
                lock,
                "locking script mismatch"
            );
            if let Some(owner) = &expected.lock.owner_hash160 {
                assert_eq!(
                    client
                        .create_lock(LockRequest {
                            owner_hash160: Some(owner.clone()),
                            value_sats: value_sats.clone(),
                            ..Default::default()
                        })
                        .unwrap(),
                    lock
                );
            }
        }
        assert_eq!(
            client
                .recognize(RecognizeRequest {
                    script: lock,
                    public_key: pubkey,
                    value_sats
                })
                .unwrap(),
            Some(expected)
        );
        if row["signature"].is_null() {
            assert!(
                client
                    .activate(Activation {
                        prevout,
                        transaction: input.transaction,
                        input_index: input.input_index,
                        sighash: input.options.sighash,
                        chronicle_active: input.options.chronicle_active,
                    })
                    .unwrap()
                    == field("signed")
            );
            continue;
        }
        let mut calls = 0;
        let mut signer = |request: SigningRequest| {
            calls += 1;
            assert_eq!(
                json!({
                    "algorithm": request.algorithm, "payloadKind": request.payload_kind,
                    "signatureFormat": request.signature_format, "sighash": request.sighash,
                }),
                row["metadata"]
            );
            let mut arguments = vec![hex::encode(&request.payload)];
            if let Some(user_id) = request.user_id {
                arguments.push(hex::encode(user_id));
            }
            assert_eq!(json!(arguments), row["arguments"]);
            Ok(hex::decode(field("signature")).unwrap())
        };
        assert!(client.sign_input(input, &mut signer).unwrap() == field("signed"));
        let payment = |fee_sats| WalletPayment {
            prevout: serde_json::from_value(row["request"]["prevout"].clone()).unwrap(),
            options: serde_json::from_value(row["request"].clone()).unwrap(),
            fee_sats,
            outputs: serde_json::from_value(row["outputs"].clone()).unwrap(),
        };
        assert!(
            client
                .sign_payment(payment("100".into()), &mut signer)
                .unwrap()
                == field("signed")
        );
        assert!(client
            .sign_payment(payment("99".into()), &mut signer)
            .is_err());
        assert_eq!(calls, 2);
    }
}
