fn main() {
    // Validate the compiled transport identity before reporting unavailable.
    // There is intentionally no local production fallback: parsing an exact
    // wire contract is not HSM/TPM custody, external replay, inhibit, watchdog,
    // or independently authenticated convergence evidence.
    if let Err(error) = sbp_lex_rust_authority_service::verify_embedded_wire_contract() {
        eprintln!("SBP_LEX_RUST_AUTHORITY_FAIL_CLOSED:{error}");
        std::process::exit(78);
    }
    eprintln!(
        "SBP_LEX_RUST_AUTHORITY_FAIL_CLOSED:PRODUCTION_AUTHORITY_DEPENDENCIES_NOT_PROVISIONED"
    );
    std::process::exit(78);
}
