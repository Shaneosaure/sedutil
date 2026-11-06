// SPDX-License-Identifier: GPL-3.0-or-later

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

const DEVICE_PREFIX: &str = r"\\.\PhysicalDrive";
const USAGE: &str = r"Usage: sedutil-rs inspect --json \\.\PhysicalDriveN
       sedutil-rs --version

Inspect a USB/SCSI disk by number on Windows x64. Run from an elevated terminal.";

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Help,
    Version,
    Inspect(u32),
}

fn parse_args(args: &[OsString]) -> Result<Action, &'static str> {
    match args {
        [] => Ok(Action::Help),
        [flag] if flag == "--help" || flag == "-h" => Ok(Action::Help),
        [flag] if flag == "--version" || flag == "-V" => Ok(Action::Version),
        [cmd, flag, device] if cmd == "inspect" && flag == "--json" => {
            let index = device
                .to_str()
                .and_then(|path| path.strip_prefix(DEVICE_PREFIX));
            let index = index
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or(r"expected a disk path of the form \\.\PhysicalDriveN")?;
            Ok(Action::Inspect(index))
        }
        _ => Err("unsupported arguments (see --help)"),
    }
}

fn run(action: Action) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = io::stdout().lock();
    match action {
        Action::Help => writeln!(out, "{USAGE}")?,
        Action::Version => writeln!(out, "sedutil-rs {}", env!("CARGO_PKG_VERSION"))?,
        #[cfg(all(windows, target_arch = "x86_64"))]
        Action::Inspect(index) => {
            let report = windows::inspect(format!("{DEVICE_PREFIX}{index}"))?;
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        Action::Inspect(_) => return Err("USB/SCSI inspection requires Windows x64".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_args(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(action) => match run(action) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "sedutil-rs: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "sedutil-rs: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect_args(path: &str) -> Vec<OsString> {
        ["inspect", "--json", path]
            .into_iter()
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn accepts_explicit_physical_disk_path() {
        assert_eq!(
            parse_args(&inspect_args(r"\\.\PhysicalDrive23")),
            Ok(Action::Inspect(23))
        );
    }

    #[test]
    fn rejects_volume_paths_and_device_path_suffixes() {
        for path in [
            "D:",
            r"\\.\C:",
            r"\\.\PhysicalDrive",
            r"\\.\PhysicalDrive+1",
            r"\\.\PhysicalDrive1\foo",
            r"\\.\PhysicalDrive4294967296",
            r"\\?\GLOBALROOT\Device\Harddisk0",
        ] {
            assert!(parse_args(&inspect_args(path)).is_err(), "{path}");
        }
    }
}
