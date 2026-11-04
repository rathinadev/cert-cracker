use cert_cracker::crypto;
use openssl::{
    hash::{MessageDigest, hash},
    sign::Signer,
};
use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn cli_audit_verifies_evidence_before_creating_state() {
    let dir = tempfile::tempdir().unwrap();
    let key = crypto::lab_key("P-256", &42u8.into()).unwrap();
    let public = dir.path().join("public.pem");
    fs::write(&public, key.public_key_to_pem().unwrap()).unwrap();
    let data = dir.path().join("signatures.json");
    let message = b"a test message";
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(message).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let digest = hash(MessageDigest::sha256(), message).unwrap();
    fs::write(&data,serde_json::to_vec(&json!({"signatures":[{"digest_hex":hex::encode(digest),"signature_der_hex":hex::encode(&signature)}]})).unwrap()).unwrap();
    let state = dir.path().join("state");
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let output = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .arg("audit-signatures")
        .arg("--input")
        .arg(&public)
        .arg("--dataset")
        .arg(&data)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["result"]["outcome"],
        "insufficient_distinct_evidence"
    );
    assert_eq!(report["result"]["verified_signatures"], 1);
    assert!(report["result"].get("private_pem").is_none());
    let wrong_state = dir.path().join("bad-state");
    fs::write(&data,serde_json::to_vec(&json!({"signatures":[{"digest_hex":"00","signature_der_hex":hex::encode(&signature)}]})).unwrap()).unwrap();
    let output = Command::new(bin)
        .arg("--state")
        .arg(&wrong_state)
        .arg("audit-signatures")
        .arg("--input")
        .arg(&public)
        .arg("--dataset")
        .arg(&data)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!wrong_state.exists());
}
