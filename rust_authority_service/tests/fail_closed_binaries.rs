use std::process::Command;

#[test]
fn programme_binary_exits_fail_closed_without_physical_dependencies() {
    let output = Command::new(env!("CARGO_BIN_EXE_sbp-lex-authority"))
        .output()
        .expect("run programme sentinel");
    assert_eq!(output.status.code(), Some(78));
    let stderr = String::from_utf8(output.stderr).expect("ASCII diagnostic");
    assert_eq!(
        stderr,
        "SBP_LEX_RUST_AUTHORITY_FAIL_CLOSED:PRODUCTION_AUTHORITY_DEPENDENCIES_NOT_PROVISIONED\n"
    );
    assert!(output.stdout.is_empty());
}

#[cfg(feature = "evidence-only-fixtures")]
#[test]
fn evidence_binary_cannot_serve_authority_artifacts() {
    let output = Command::new(env!("CARGO_BIN_EXE_sbp-lex-authority-evidence"))
        .output()
        .expect("run evidence sentinel");
    assert_eq!(output.status.code(), Some(78));
    let stderr = String::from_utf8(output.stderr).expect("ASCII diagnostic");
    assert_eq!(
        stderr,
        "SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY:INDEPENDENT_CONVERGENCE_EVIDENCE_REQUIRED\n"
    );
    assert!(output.stdout.is_empty());
}
