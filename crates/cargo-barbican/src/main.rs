use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    match cargo_barbican::run(&mut stdout, &mut stderr) {
        Ok(code) => code,
        Err(error) => {
            // `cargo_barbican::run` already routes ordinary failures through
            // its own FAIL-prefixed renderer; this only fires if even that
            // renderer's stderr write failed, so there is nowhere left to
            // report except a last-resort line here.
            eprintln!("FAIL {error}");
            ExitCode::from(1)
        }
    }
}
