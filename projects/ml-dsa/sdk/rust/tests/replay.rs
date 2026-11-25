#[path = "../../../../../shared/sdk/tests/rust.rs"]
mod replay;

#[test]
fn reference_replay() {
    replay::replay(bsv_script_lab_mldsa_sdk::client);
}
