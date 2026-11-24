use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

type DynError = Box<dyn std::error::Error>;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{e}");
        std::process::exit(-1);
    }
}

fn try_main() -> Result<(), DynError> {
    let task = env::args().nth(1);
    match task.as_deref() {
        Some("driver") => produce_driver()?,
        Some("client") => produce_client()?,
        _ => print_help(),
    }
    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:
         - driver: build the driver and rename ramon.dll to ramon.sys
         - client: build the user-mode client"
    )
}

fn produce_driver() -> Result<(), DynError> {
    // the driver builds from its own directory: .cargo/config.toml carries the link flags
    let driver_dir = project_root().join("ramon-km");
    build(&driver_dir, "ramon", &["--release"])?;

    let dll = release_dir().join("ramon.dll");
    let sys = dll.with_extension("sys");
    fs::copy(&dll, &sys)?;
    println!("{}", sys.display());
    Ok(())
}

fn produce_client() -> Result<(), DynError> {
    build(&project_root(), "ramon-client", &["--release", "-p", "ramon-client"])?;
    Ok(())
}

fn build(dir: &Path, what: &str, args: &[&str]) -> Result<(), DynError> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo).current_dir(dir).args(args).status()?;
    if !status.success() {
        return Err(format!("cargo build failed for {what}").into());
    }
    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(1).unwrap().to_path_buf()
}

fn release_dir() -> PathBuf {
    project_root().join("target/release")
}
