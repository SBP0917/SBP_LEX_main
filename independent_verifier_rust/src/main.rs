#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

use sbp_lex_independent_verifier::verify;

fn read_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input)
    } else {
        fs::read_to_string(path)
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let program = args
        .next()
        .and_then(|s| s.into_string().ok())
        .unwrap_or_else(|| "sbp-lex-independent-verify".to_owned());
    let Some(path) = args.next().and_then(|s| s.into_string().ok()) else {
        eprintln!("usage: {program} <evidence-file|->");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: {program} <evidence-file|->");
        return ExitCode::from(2);
    }

    let input = match read_input(&path) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("unable to read evidence: {error}");
            return ExitCode::from(2);
        }
    };

    // Deliberately no fixture or fallback verifier exists in the production
    // binary. A downstream deployment must link its approved provider.
    match verify(&input, None) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("evidence rejected: {error}");
            ExitCode::from(1)
        }
    }
}
