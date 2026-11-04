use cert_cracker::{calibration::Profile, crypto};
use serde_json::Value;
use std::{fs, process::Command};

#[test]
fn calibration_and_estimates_are_local_and_reject_mismatched_resources() {
    let temp = tempfile::tempdir().unwrap();
    let profile = temp.path().join("profile.json");
    let state = temp.path().join("state");
    let cert = temp.path().join("cert.pem");
    let (certificate, _) = crypto::lab_certificate("P-256", &4u8.into()).unwrap();
    fs::write(&cert, certificate).unwrap();
    let bin = env!("CARGO_BIN_EXE_cert-cracker");
    let output = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args([
            "calibrate",
            "--candidates",
            "1000",
            "--workers",
            "2",
            "--memory-mib",
            "16",
            "--repetitions",
            "1",
            "--output",
        ])
        .arg(&profile)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(profile.is_file());
    assert!(!state.exists());
    for cooperative in [false, true] {
        let mut cmd = Command::new(bin);
        cmd.arg("--state")
            .arg(&state)
            .args(["estimate", "--input"])
            .arg(&cert)
            .args([
                "--end",
                "10001",
                "--workers",
                "2",
                "--memory-mib",
                "16",
                "--calibration",
            ])
            .arg(&profile);
        if cooperative {
            cmd.args(["--method", "kangaroo", "--kangaroo-cooperative"]);
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["persistent_state_created"], false);
        assert_eq!(
            report["planning"]["calibration"]["environment_fields_match"],
            true
        );
        assert!(
            report["planning"]["calibration"]["sequential_seconds"]
                .as_f64()
                .unwrap()
                > 0.0
        );
        if cooperative {
            assert!(
                report["planning"]["calibration"]["kangaroo_maximum_step_budget_seconds"]
                    .as_f64()
                    .unwrap()
                    > 0.0
            );
        } else {
            assert!(
                report["planning"]["calibration"]["bsgs_seconds"]
                    .as_f64()
                    .unwrap()
                    > 0.0
            );
        }
    }
    let output = Command::new(bin)
        .arg("--state")
        .arg(&state)
        .args(["estimate", "--input"])
        .arg(&cert)
        .args([
            "--end",
            "10001",
            "--workers",
            "1",
            "--memory-mib",
            "16",
            "--calibration",
        ])
        .arg(&profile)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("calibration workers or memory budget differ")
    );
    assert!(!state.exists());
}

#[test]
fn malformed_and_oversized_profiles_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profile.json");
    fs::write(&path, b"{}").unwrap();
    assert!(Profile::load(&path).is_err());
    fs::write(&path, vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(
        Profile::load(&path)
            .unwrap_err()
            .to_string()
            .contains("exceeds 256 KiB")
    );
}
