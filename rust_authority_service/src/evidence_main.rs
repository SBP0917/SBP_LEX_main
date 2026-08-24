fn main() {
    // A separately named binary prevents an evidence fixture from masquerading
    // as programme authority. The exact wire parser is integrated, but its
    // caller-supplied convergence digests are not independent evidence, so this
    // build must not enter PREPARE/COMMIT or serve authority artifacts.
    if let Err(error) = sbp_lex_rust_authority_service::verify_embedded_wire_contract() {
        eprintln!("SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY:{error}");
        std::process::exit(78);
    }
    eprintln!("SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY:INDEPENDENT_CONVERGENCE_EVIDENCE_REQUIRED");
    std::process::exit(78);
}
