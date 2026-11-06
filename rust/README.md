# sedutil-rs · Windows USB/SCSI alpha

`sedutil-rs inspect --json` reads the identity and TCG Opal Discovery 0 data
of an explicitly selected USB disk on Windows x64. It sends standard SCSI
INQUIRY and SECURITY PROTOCOL IN. Windows requires a read/write handle for
this pass-through IOCTL, so use an elevated terminal. The separate
`inspect-lr0` command reads the global locking range via an authenticated
Opal session.

The JSON includes the Windows serial number when available, SCSI identity,
Discovery feature codes, Locking flags and the Opal V2 ComID. Feature codes
are decimal JSON integers. `media_encryption`, `locking_enabled` and `locked`
are separate observations. Discovery 0 does not expose the detailed LR0 state.
The serial number is disk-identifying data and can be redacted before sharing
the output.

The reported `legacy_scsi_salt_hex` is the eight unmodified INQUIRY Vendor ID
bytes followed by twelve zero bytes. This is the explicit compatibility
profile for disks initialized through the sedutil 1.20.0 Linux SCSI path. The
RustCrypto PBKDF2-HMAC-SHA1 implementation derives the Admin1 HostChallenge
using the same 75,000 iterations and 32-byte output as the reference
implementation. The regression tests use public test inputs. The reference
implementation is the C++ tag `sedutil-win-v0.1.0-rc.1` at
`cbd3c5187b24e19ce9a4241e40ab2e55f902df6a`.

The parser follows TCG Storage Architecture Core 2.01 §3.3.6 and reads the
Opal V2 fields defined in the Opal SSC. The Windows transport checks the
adapter's alignment mask, actual transfer length, SCSI status and sense
bounds. [TCG Core](https://trustedcomputinggroup.org/resource/tcg-storage-architecture-core-specification/)
· [Opal SSC](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Storage-Opal-SSC-v2.30_pub.pdf)
· [Windows SCSI pass-through](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddscsi/ni-ntddscsi-ioctl_scsi_pass_through_direct)

## Build and test

Install Rust with [rustup](https://rustup.rs/). For Windows, install the x64
Visual C++ tools and Windows SDK from Visual Studio Build Tools. Run the
commands from this `rust/` directory so rustup and Cargo pick up the pinned
toolchain and the Windows CFG and CET linker settings.

```text
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

On Windows x64, build and smoke-test the release executable.

```powershell
cargo build --locked --release --target x86_64-pc-windows-msvc
.\target\x86_64-pc-windows-msvc\release\sedutil-rs.exe --version
```

On Linux or WSL, run the synthetic parser corpus under libFuzzer.

```bash
rustup toolchain install nightly-2026-11-05 --profile minimal
cargo install --locked --version 0.13.2 cargo-fuzz
mkdir -p fuzz/corpus/device_response
cargo +nightly-2026-11-05 fetch --locked --manifest-path fuzz/Cargo.toml
CARGO_NET_OFFLINE=true cargo +nightly-2026-11-05 fuzz run device_response \
  fuzz/corpus/device_response tests/fixtures -- -max_len=2048 -max_total_time=30
```

For a local dependency audit, install
[cargo-deny 0.20.2](https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.20.2)
and check both lockfiles from this directory.

```text
cargo deny --locked check
cargo deny --locked --manifest-path fuzz/Cargo.toml --config deny.toml check
```

## Hardware acceptance test

In elevated PowerShell, identify the T7 by its model, serial number, USB bus
and capacity. Disk numbers can change after reconnecting the drive.

```powershell
Get-Disk | Select-Object Number, FriendlyName, SerialNumber, BusType, Size
```

Replace `N` with the number of that exact disk. Use the C++ pre-release from
its own directory for the comparison.

```powershell
.\target\x86_64-pc-windows-msvc\release\sedutil-rs.exe inspect --json '\\.\PhysicalDriveN'
.\sedutil-cli.exe --legacy-scsi-salt --query --json '\\.\PhysicalDriveN'
```

Compare the derived salt, Opal V2 base ComID and the Locking flags. Record
the OS, model, firmware and bridge/driver together with the result. The test
fixtures are synthetic. Support for a specific drive and firmware requires
this hardware check.

## Read global locking range (LR0)

Use elevated PowerShell. Verify the disk identity and set `$serial` to the
Windows serial number of the intended device. This command checks it again
on the same device handle before prompting.

```powershell
.\target\x86_64-pc-windows-msvc\release\sedutil-rs.exe inspect-lr0 --legacy-scsi-salt --serial $serial --json $device
```

Use the existing Admin1 password from the sedutil 1.20.0 Linux SCSI profile.
The console prompt masks input and the CLI submits one authentication
attempt. A rejected attempt may count toward the device's lockout policy.
The CLI uses an Opal read-only session, reads columns 3 through 8 of the
global locking range and checks that the TPer acknowledges the session
close. Support for read-only sessions varies by firmware. On a device that
rejects the read-only session parameters, append `--compat-rw-session` to
explicitly request a read/write Opal session, as the reference CLI does.
The requested operation remains a GET of LR0. The command attempts one
session in the chosen mode and reports the mode as `session_mode`.

The `lr0` object contains `range_start`, `range_length`, and the read and
write enable and lock flags. The existing `discovery` object still describes
the drive-wide Discovery 0 state. On error, the command returns a nonzero
exit status and reports the failed stage or Opal status.

## Unlock global locking range (LR0)

Select the intended USB disk in elevated PowerShell and set `$serial` to its
Windows serial number and `$device` to its physical drive path.

```powershell
.\target\x86_64-pc-windows-msvc\release\sedutil-rs.exe unlock-lr0 --legacy-scsi-salt --serial $serial --json $device
```

This command authenticates once as Admin1 in a read/write session. It reads
LR0 before sending a single Set of `ReadLocked` and `WriteLocked` to false.
It skips the Set when both bits are already clear. A second Get after Set
verifies both lock bits and the prior range geometry and locking-enable
settings before the CLI closes the session. The JSON reports `changed`,
`lr0_before` and the verified `lr0` state.

On an ambiguous Set response or failed readback, inspect LR0 separately
before retrying. Authentication or Set is never resent automatically.
For hardware acceptance, verify that Windows can read the test volume and
compare the SHA-256 of a known witness file against its baseline digest.
For the Global Range, the Opal RangeStart and RangeLength table values are
both zero even though LR0 covers the user-addressable LBA range.

## CI, release and maintenance

- Rust CI runs on branch pushes and PRs. It tests on Ubuntu and Windows,
  fuzzes the parser on Linux, checks both Cargo lockfiles against RustSec and
  the local dependency policy, and scans Rust and Actions workflows with
  CodeQL. The scheduled run starts after the workflow reaches the default
  branch. A Windows x64 ZIP is downloadable from the run's Artifacts.
- The release job consumes the Windows ZIP from the same run after the
  tests, fuzzing and scans finish. A signed annotated tag matching the Cargo
  version triggers publication. The job verifies the tag signature through
  GitHub, verifies the checksum and attests the ZIP before creating the
  prerelease. On the tested commit, the current version's tag is
  `sedutil-rs-v0.1.0-alpha.3`. Use `git tag -s` and push only that tag.
- Enable Actions on the fork. Use this workflow as the advanced CodeQL
  setup. Disable the GitHub CodeQL default setup if it is active because it
  conflicts with SARIF uploads from this workflow. Enable Dependabot alerts
  and security updates in repository settings. Weekly version updates for
  Cargo and Actions use `.github/dependabot.yml` from the default branch and
  require opting into version updates on the fork. Configure push
  protection and require the tests and scans on the integration branch.
- Check provenance after downloading a published ZIP with
  `gh attestation verify <archive.zip> --repo Shaneosaure/sedutil`. Compare
  its SHA-256 with `SHA256SUMS.txt`.

## Roadmap and acceptance criteria

| Milestone | Acceptance criterion |
| --- | --- |
| USB/SCSI inspection | The Rust and C++ tools agree on the test T7's salt, ComID and Locking flags. |
| Authenticated inspection | Read LR0 with the existing Admin1 credential via masked input. Select the compatibility profile explicitly and bound authentication to one attempt. Test malformed Opal packet and token responses and timeouts using replay fixtures. |
| Lock and unlock | Verify the selected physical drive by identity. Complete a lock, USB power cycle and unlock with the test file's SHA-256 preserved. |
| Provision and PSID Revert | Gate destructive operations on the exact disk identity and confirmation. Verify the post-operation state and handle ambiguous completion without automatic retries. Validate on expendable media. |
| Expand transport support | Add NVMe, SATA and Linux one transport at a time, with the same protocol fixtures and a hardware matrix. |
