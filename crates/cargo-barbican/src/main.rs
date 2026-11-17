use std::process::ExitCode;

fn main() -> ExitCode {
    match cargo_barbican::run_stdio() {
        Ok(code) => code,
        Err(error) => {
            // `cargo_barbican::run_stdio` already routes ordinary failures through
            // its own FAIL-prefixed renderer; this only fires if even that
            // renderer's stderr write failed, so there is nowhere left to
            // report except a last-resort line here.
            eprintln!("FAIL {error}");
            ExitCode::from(1)
        }
    }
}
