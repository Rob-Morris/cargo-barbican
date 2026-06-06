use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    match cargo_barbican::run(&mut stdout, &mut stderr) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("cargo-barbican: {error}");
            ExitCode::from(1)
        }
    }
}
