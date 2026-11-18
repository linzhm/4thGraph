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
