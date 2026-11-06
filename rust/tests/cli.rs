// SPDX-License-Identifier: GPL-3.0-or-later

use std::process::Command;

#[test]
fn version_and_help_work_without_a_device() {
    let exe = env!("CARGO_BIN_EXE_sedutil-rs");
    let help = Command::new(exe).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("inspect --json"));
    let version = Command::new(exe).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        concat!("sedutil-rs ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn destructive_commands_and_volume_paths_are_rejected_by_the_cli() {
    let exe = env!("CARGO_BIN_EXE_sedutil-rs");
    for args in [
        &["psid-revert", r"\\.\PhysicalDrive0"][..],
        &["inspect", "--json", "D:"][..],
    ] {
        let out = Command::new(exe).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
}
