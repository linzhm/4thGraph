use p2pkh_r1_deferred::{
    activation_witness, activation_witness_with_digest, lock_for_key, lock_for_owner, recognize,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn v01_public_vectors() {
    check_vectors(
        include_str!("../../../template/template.hex"),
        include_str!("../../../../p2pkh-r1/template/template.hex"),
        include_str!("../../../../p2pkh-r1/template/v0.2.0/template.hex"),
        include_str!("../../../template/layout.json"),
        include_str!("../../../template/activation-single.json"),
        include_str!("../../../template/sighash-modes.json"),
    );
}

#[test]
fn v02_public_vectors() {
    check_vectors(
        include_str!("../../../template/v0.2.0/template.hex"),
        include_str!("../../../../p2pkh-r1/template/v0.2.0/template.hex"),
        include_str!("../../../../p2pkh-r1/template/template.hex"),
        include_str!("../../../template/v0.2.0/layout.json"),
        include_str!("../../../template/v0.2.0/activation-single.json"),
        include_str!("../../../template/v0.2.0/sighash-modes.json"),
    );
}

fn check_vectors(
    deferred_template: &str,
    r1_template: &str,
    other_r1_template: &str,
    layout_json: &str,
    activation_json: &str,
    modes_json: &str,
) {
    let decode_template =
        |text: &str| hex::decode(text.split_whitespace().collect::<String>()).unwrap();
    let template = decode_template(deferred_template);
    let r1 = decode_template(r1_template);
    let other_r1 = decode_template(other_r1_template);
    let layout: Value = serde_json::from_str(layout_json).unwrap();
    let activation: Value = serde_json::from_str(activation_json).unwrap();
    let modes: Value = serde_json::from_str(modes_json).unwrap();

    for vector in layout["vectors"].as_array().unwrap() {
        let value = vector["value_sats"].as_u64().unwrap();
        let field = |name: &str| vector[name].as_str().unwrap();
        let key = hex::decode(field("public_key_x963")).unwrap();
        let owner: [u8; 20] = hex::decode(field("owner_hash160"))
            .unwrap()
            .try_into()
            .unwrap();
        let script = lock_for_key(&template, &r1, &key, value).unwrap();
        assert_eq!(
            script,
            lock_for_owner(&template, &r1, &owner, value).unwrap()
        );
        assert_eq!(
            hex::encode(Sha256::digest(&script)),
            field("locking_script_sha256")
        );
        let recognized = recognize(&r1, &script, value).unwrap();
        assert_eq!(recognized.owner_hash160, owner);
        assert!(recognized.public_key.is_none());
        assert_eq!(
            hex::encode(recognized.target_script_sha256),
            field("target_script_sha256")
        );
        assert_eq!(
            hex::encode(recognized.target_txout_hash256),
            field("target_txout_hash256")
        );
        assert!(recognize(&r1, &script, value + 1).is_none());
        assert!(recognize(&other_r1, &script, value).is_none());
        let mut legacy = vec![65];
        legacy.extend_from_slice(&key);
        legacy.extend_from_slice(&script[21..]);
        assert_eq!(
            hex::encode(Sha256::digest(&legacy)),
            field("legacy_locking_script_sha256")
        );
        let recognized_legacy = recognize(&r1, &legacy, value).unwrap();
        assert_eq!(
            recognized_legacy.public_key.as_ref().unwrap().as_slice(),
            key
        );
        assert_eq!(recognized_legacy.owner_hash160, recognized.owner_hash160);
        assert_eq!(
            recognized_legacy.target_script_sha256,
            recognized.target_script_sha256
        );
        assert_eq!(
            recognized_legacy.target_txout_hash256,
            recognized.target_txout_hash256
        );
        if vector["id"] == activation["vector_id"] {
            let mut preimage =
                hex::decode(activation["activation_preimage_hex"].as_str().unwrap()).unwrap();
            let witness = activation_witness(&r1, &script, value, &preimage).unwrap();
            assert_eq!(
                hex::encode(witness),
                activation["unlocking_script_hex"].as_str().unwrap()
            );
            preimage[118] ^= 1;
            assert!(activation_witness(&r1, &script, value, &preimage).is_err());
            for mode in modes["cases"].as_array().unwrap() {
                let paired =
                    hex::decode(mode["activation_preimage_hex"].as_str().unwrap()).unwrap();
                let mut auxiliary = hex::decode(mode["auxiliary_hex"].as_str().unwrap()).unwrap();
                let extra = (!auxiliary.is_empty()).then_some(auxiliary.as_slice());
                let witness =
                    activation_witness_with_digest(&r1, &script, value, &paired, extra).unwrap();
                assert_eq!(
                    hex::encode(witness),
                    mode["unlocking_script_hex"].as_str().unwrap()
                );
                if !auxiliary.is_empty() {
                    auxiliary[0] ^= 0x80;
                    assert!(activation_witness_with_digest(
                        &r1,
                        &script,
                        value,
                        &paired,
                        Some(&auxiliary)
                    )
                    .is_err());
                }
            }
        }
    }
}
