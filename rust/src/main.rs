// SPDX-License-Identifier: GPL-3.0-or-later

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::process::ExitCode;

#[cfg(any(test, all(windows, target_arch = "x86_64")))]
mod opal;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

const DEVICE_PREFIX: &str = r"\\.\PhysicalDrive";
const USAGE: &str = r"Usage: sedutil-rs inspect --json \\.\PhysicalDriveN
       sedutil-rs inspect-lr0 --legacy-scsi-salt --serial SERIAL --json \\.\PhysicalDriveN [--compat-rw-session]
       sedutil-rs unlock-lr0 --legacy-scsi-salt --serial SERIAL --json \\.\PhysicalDriveN
       sedutil-rs lock-lr0 --legacy-scsi-salt --serial SERIAL --json \\.\PhysicalDriveN
       sedutil-rs --version

Inspect a USB/SCSI disk or change its global locking range state on Windows x64.
Run from an elevated terminal. The lock command requires an offline disk.";

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Help,
    Version,
    Inspect(u32),
    InspectLr0 {
        index: u32,
        serial: String,
        compat_rw_session: bool,
    },
    SetLr0 {
        index: u32,
        serial: String,
        locked: bool,
    },
}

fn parse_args(args: &[OsString]) -> Result<Action, &'static str> {
    match args {
        [] => Ok(Action::Help),
        [flag] if flag == "--help" || flag == "-h" => Ok(Action::Help),
        [flag] if flag == "--version" || flag == "-V" => Ok(Action::Version),
        [cmd, flag, device] if cmd == "inspect" && flag == "--json" => {
            Ok(Action::Inspect(disk_index(device)?))
        }
        [
            cmd,
            profile,
            serial_flag,
            serial,
            json,
            device,
            options @ ..,
        ] if (cmd == "inspect-lr0" || cmd == "unlock-lr0" || cmd == "lock-lr0")
            && profile == "--legacy-scsi-salt"
            && serial_flag == "--serial"
            && json == "--json"
            && (options.is_empty()
                || (cmd == "inspect-lr0"
                    && matches!(options, [flag] if flag == "--compat-rw-session"))) =>
        {
            let serial = serial
                .to_str()
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= 256
                        && s.trim() == *s
                        && s.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
                })
                .ok_or("expected a nonempty printable disk serial number")?;
            let index = disk_index(device)?;
            let serial = serial.to_owned();
            if cmd == "inspect-lr0" {
                Ok(Action::InspectLr0 {
                    index,
                    serial,
                    compat_rw_session: !options.is_empty(),
                })
            } else {
                Ok(Action::SetLr0 {
                    index,
                    serial,
                    locked: cmd == "lock-lr0",
                })
            }
        }
        _ => Err("unsupported arguments (see --help)"),
    }
}

fn disk_index(device: &OsStr) -> Result<u32, &'static str> {
    device
        .to_str()
        .and_then(|path| path.strip_prefix(DEVICE_PREFIX))
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or(r"expected a disk path of the form \\.\PhysicalDriveN")
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
        #[cfg(all(windows, target_arch = "x86_64"))]
        Action::InspectLr0 {
            index,
            serial,
            compat_rw_session,
        } => {
            let report = windows::inspect_lr0(
                format!("{DEVICE_PREFIX}{index}"),
                &serial,
                compat_rw_session,
            )?;
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
        }
        #[cfg(all(windows, target_arch = "x86_64"))]
        Action::SetLr0 {
            index,
            serial,
            locked,
        } => {
            let report = windows::set_lr0(format!("{DEVICE_PREFIX}{index}"), &serial, locked)?;
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        Action::Inspect(_) | Action::InspectLr0 { .. } | Action::SetLr0 { .. } => {
            return Err("USB/SCSI inspection requires Windows x64".into());
        }
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
    fn lr0_requires_the_explicit_profile_and_serial() {
        let mut args: Vec<OsString> = [
            "inspect-lr0",
            "--legacy-scsi-salt",
            "--serial",
            "T7-123",
            "--json",
            r"\\.\PhysicalDrive23",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(
            parse_args(&args),
            Ok(Action::InspectLr0 {
                index: 23,
                serial: "T7-123".into(),
                compat_rw_session: false
            })
        );
        args.push("--compat-rw-session".into());
        assert_eq!(
            parse_args(&args),
            Ok(Action::InspectLr0 {
                index: 23,
                serial: "T7-123".into(),
                compat_rw_session: true,
            })
        );
        args.push("--compat-rw-session".into());
        assert!(parse_args(&args).is_err());
        args.truncate(6);
        args[1] = "--password".into();
        assert!(parse_args(&args).is_err());
        args[1] = "--legacy-scsi-salt".into();
        args[3] = "".into();
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn lock_and_unlock_require_the_serial_and_legacy_profile() {
        let mut args: Vec<OsString> = [
            "unlock-lr0",
            "--legacy-scsi-salt",
            "--serial",
            "T7-123",
            "--json",
            r"\\.\PhysicalDrive23",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(
            parse_args(&args),
            Ok(Action::SetLr0 {
                index: 23,
                serial: "T7-123".into(),
                locked: false,
            })
        );
        args[0] = "lock-lr0".into();
        assert_eq!(
            parse_args(&args),
            Ok(Action::SetLr0 {
                index: 23,
                serial: "T7-123".into(),
                locked: true,
            })
        );
        args.push("--compat-rw-session".into());
        assert!(parse_args(&args).is_err());
        args.truncate(6);
        args[3] = "".into();
        assert!(parse_args(&args).is_err());
        args[3] = "T7-123".into();
        args[1] = "--password".into();
        assert!(parse_args(&args).is_err());
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
