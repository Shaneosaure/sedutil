// SPDX-License-Identifier: GPL-3.0-or-later
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sedutil_rs::{discovery::Discovery, inquiry::Inquiry};

fuzz_target!(|input: &[u8]| {
    let _ = Discovery::parse(input);
    if let Ok(inquiry) = Inquiry::parse(input) {
        let _ = inquiry.legacy_scsi_salt();
    }
});
