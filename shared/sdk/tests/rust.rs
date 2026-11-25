use bsv_script_lab_local_sdk::{Config, LocalClient, Output, Payment, Recognition, Spend};
use serde_json::Value;
use std::{env, fs, path::PathBuf};

pub fn replay(factory: fn(Config) -> LocalClient) {
    let Ok(path) = env::var("SCRIPT_LAB_SDK_VECTOR") else {
        eprintln!("generate a public integration vector with shared/sdk/tests/vector.py");
        return;
    };
    let source = fs::read(path).unwrap();
    let rows: Vec<Value> = serde_json::from_slice(&source).unwrap();
    assert!(!rows.is_empty(), "missing integration cases");
    let client = factory(Config {
        python: PathBuf::from(
            env::var("SCRIPT_LAB_SDK_PYTHON").unwrap_or_else(|_| "python3".into()),
        ),
        bridge: PathBuf::from(env::var("SCRIPT_LAB_SDK_BRIDGE").unwrap()),
    });
    for row in rows {
        let field = |name: &str| row[name].as_str().unwrap();
        let mut request: Spend = serde_json::from_value(row["request"].clone()).unwrap();
        let lock = client
            .lock(&request.options.public_key, Some(field("profile")))
            .unwrap();
        assert!(lock == field("lock"), "locking script mismatch");
        let recognized = client
            .recognize(&lock, Some(&request.options.public_key))
            .unwrap();
        let expected: Recognition = serde_json::from_value(row["recognition"].clone()).unwrap();
        if let Some(owner) = &expected.owner_hash160 {
            assert!(client.lock_for_owner(owner).unwrap() == lock);
        }
        assert_eq!(recognized, Some(expected));
        assert_eq!(
            client
                .recognize(
                    &format!("00{}", &lock[2..]),
                    Some(&request.options.public_key)
                )
                .unwrap(),
            None
        );
        let outputs: Vec<Output> = serde_json::from_value(row["outputs"].clone()).unwrap();
        let mut calls = 0;
        let mut signer = |arguments: &[Vec<u8>]| {
            calls += 1;
            assert_eq!(
                serde_json::json!(arguments.iter().map(hex::encode).collect::<Vec<_>>()),
                row["arguments"]
            );
            Ok(hex::decode(field("signature")).unwrap())
        };
        let mut payment = Payment {
            options: serde_json::from_value(row["request"].clone()).unwrap(),
            outputs,
            fee_sats: "100".into(),
        };
        assert!(client.sign_spend(request, &mut signer).unwrap() == field("signed"));
        assert!(client.sign_payment(payment, &mut signer).unwrap() == field("signed"));
        request = serde_json::from_value(row["request"].clone()).unwrap();
        payment = Payment {
            options: serde_json::from_value(row["request"].clone()).unwrap(),
            outputs: serde_json::from_value(row["outputs"].clone()).unwrap(),
            fee_sats: "99".into(),
        };
        assert!(client.sign_payment(payment, &mut signer).is_err());
        assert_eq!(calls, 2);
        assert!(client.sign_spend(request, |_| Ok(vec![0])).is_err());
    }
}
