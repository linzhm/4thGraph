use p2pkh_r1::{lock_for_key, lock_for_owner, recognize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn public_vectors() {
    let layout: Value = serde_json::from_str(include_str!("../../../template/layout.json")).unwrap();
    let base = hex::decode(include_str!("../../../template/template.hex").split_whitespace().collect::<String>()).unwrap();
    for vector in layout["vectors"].as_array().unwrap() {
        let owner: [u8; 20] = hex::decode(vector["owner_hash160"].as_str().unwrap()).unwrap().try_into().unwrap();
        let script = lock_for_owner(&base, &owner).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&script)), vector["script_sha256"].as_str().unwrap());
        assert_eq!(recognize(&script), Some(owner));
        if let Some(key) = vector["public_key_x963"].as_str() {
            assert_eq!(lock_for_key(&base, &hex::decode(key).unwrap()).unwrap(), script);
        }
    }
    assert_eq!(hex::encode(Sha256::digest(&base)), layout["base_script_sha256"].as_str().unwrap());
    for i in [0, 100, 207, 228, base.len() - 1] {
        let mut changed = base.clone();
        changed[i] ^= 1;
        assert_eq!(recognize(&changed), None);
        assert!(lock_for_owner(&changed, &[0; 20]).is_err());
    }
    assert_eq!(recognize(&base[1..]), None);
    let mut extra = base.clone();
    extra.push(0);
    assert_eq!(recognize(&extra), None);
    assert!(lock_for_key(&base, &[0; 32]).is_err());
    let mut off_curve = [0; 65];
    off_curve[0] = 4;
    assert!(lock_for_key(&base, &off_curve).is_err());
}

#[test]
fn ordinary_payment() {
    assert_payment(include_str!("../../../template/template.hex"),
                   include_str!("../../../template/spend-all.json"));
    assert_payment(include_str!("../../../template/candidates/compiled.hex"),
                   include_str!("../../../template/candidates/spend-all.json"));
    assert_payment(include_str!("../../../template/candidates/scheduled.hex"),
                   include_str!("../../../template/candidates/scheduled-spend-all.json"));
}

fn assert_payment(template: &str, vector: &str) {
    use p2pkh_r1::payment::{sign_payment, sign_payment_with_message, Output, Payment};
    let v: Value = serde_json::from_str(vector).unwrap();
    let dec = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
    let base = hex::decode(template.split_whitespace().collect::<String>()).unwrap();
    let key = dec("public_key_x963");
    let mut payment = Payment {
        txid: dec("parent_txid").try_into().unwrap(), vout: 0, input_satoshis: 1000,
        input_script: lock_for_key(&base, &key).unwrap(),
        outputs: vec![Output { satoshis: 900, script: vec![0x51] }], fee: 100,
    };
    assert_eq!(recognize(&payment.input_script), Some(dec("owner_hash160").try_into().unwrap()));
    let mut changed = payment.input_script.clone();
    changed[228] ^= 1;
    assert_eq!(recognize(&changed), None);
    let tx = sign_payment(&payment, &key, |digest| {
        assert_eq!(digest.as_slice(), dec("digest_hex"));
        Ok(dec("signature_hex").try_into().unwrap())
    }).unwrap();
    let message_signed = sign_payment_with_message(&payment, &key, |message| {
        assert_eq!(message, <[u8; 32]>::from(Sha256::digest(dec("preimage_hex"))));
        Ok(dec("signature_hex").try_into().unwrap())
    }).unwrap();
    assert_eq!(message_signed, tx);
    let mut txid = Sha256::digest(Sha256::digest(&tx));
    txid.reverse();
    assert_eq!(hex::encode(txid), v["signed_txid"].as_str().unwrap());
    let witness = dec("script_sig_hex");
    assert!(tx.windows(witness.len()).any(|w| w == witness));
    assert!(sign_payment(&payment, &key, |_| Ok([0; 64])).is_err());
    payment.fee -= 1;
    assert!(sign_payment(&payment, &key, |_| panic!("unexpected signer")).is_err());
}
