// SPDX-License-Identifier: GPL-3.0-or-later

use pbkdf2::pbkdf2_hmac_array;
use sedutil_rs::{discovery::Discovery, inquiry::Inquiry};
use sha1::Sha1;

// Synthetic protocol fixtures. The PBKDF2 vectors match the C++ pre-release.
const INQUIRY: &[u8; 36] = include_bytes!("fixtures/inquiry.bin");
const DISCOVERY: &[u8] = include_bytes!("fixtures/discovery.bin");

#[test]
fn parses_inquiry_and_preserves_raw_vendor_bytes_for_legacy_salt() {
    let inquiry = Inquiry::parse(INQUIRY).unwrap();
    assert_eq!(inquiry.vendor_id(), "Samsung");
    assert_eq!(inquiry.product_id(), "PSSD T7");
    assert_eq!(inquiry.revision(), "0001");
    let mut expected = [0; 20];
    expected[..8].copy_from_slice(b"Samsung ");
    assert_eq!(inquiry.legacy_scsi_salt(), expected);
}

#[test]
fn rejects_incomplete_or_unsuitable_inquiry() {
    for n in 0..INQUIRY.len() {
        assert!(Inquiry::parse(&INQUIRY[..n]).is_err(), "prefix {n}");
    }
    let mut invalid = *INQUIRY;
    invalid[0] = 0x1f;
    assert!(Inquiry::parse(&invalid).is_err());
    invalid[0] = 0;
    invalid[4] = 30;
    assert!(Inquiry::parse(&invalid).is_err());
}

#[test]
fn matches_the_two_cpp_pbkdf2_compatibility_vectors() {
    let mut inquiry = *INQUIRY;
    for (vendor, expected) in [
        (
            b"VEN\0DOR ",
            "28d7108209525576ab2701cd919c2a3027d8f39d2c5eb1db5f8b2d8a55332c9f",
        ),
        (
            b"Samsung ",
            "1bc5e27dbd51bb10c5012ae2f002ce69a610ff4bd6eb0e5a80b9f02da879e78b",
        ),
    ] {
        inquiry[8..16].copy_from_slice(vendor);
        let salt = Inquiry::parse(&inquiry).unwrap().legacy_scsi_salt();
        let hash = pbkdf2_hmac_array::<Sha1, 32>(b"password", &salt, 75_000);
        let actual: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn decodes_discovery_flags_and_com_id_independently_of_transport_padding() {
    let mut bytes = DISCOVERY.to_vec();
    bytes.resize(2048, 0x5a);
    let parsed = Discovery::parse(&bytes).unwrap();
    assert_eq!(parsed, Discovery::parse(DISCOVERY).unwrap());
    assert_eq!((parsed.major_version, parsed.minor_version), (0, 1));
    assert_eq!(parsed.feature_codes, [1, 2, 0x0203, 0xc001]);
    let tper = parsed.tper.unwrap();
    assert!(tper.sync && tper.async_supported);
    let locking = parsed.locking.unwrap();
    assert!(locking.media_encryption && locking.locking_enabled && locking.locking_supported);
    assert!(!locking.locked);
    let opal = parsed.opal_v2.unwrap();
    assert_eq!((opal.descriptor_version, opal.ssc_minor_version), (2, 2));
    assert_eq!((opal.base_com_id, opal.number_of_com_ids), (0x1004, 1));
    bytes[68] |= 0x04;
    assert!(Discovery::parse(&bytes).unwrap().locking.unwrap().locked);
}

#[test]
fn rejects_every_truncated_discovery_prefix_and_out_of_bounds_lengths() {
    for n in 0..DISCOVERY.len() {
        assert!(Discovery::parse(&DISCOVERY[..n]).is_err(), "prefix {n}");
    }
    let mut bytes = DISCOVERY.to_vec();
    for length in [0u32, 43, 45, 48, u32::MAX] {
        bytes[..4].copy_from_slice(&length.to_be_bytes());
        assert!(Discovery::parse(&bytes).is_err(), "declared {length}");
    }
    bytes.copy_from_slice(DISCOVERY);
    bytes[51] = 0xfc; // TPer body extends past the declared response.
    assert!(Discovery::parse(&bytes).is_err());
    bytes[51] = 4; // Fits within the response, too short for TPer.
    assert!(Discovery::parse(&bytes).is_err());
    bytes[51] = 13;
    assert_eq!(
        Discovery::parse(&bytes),
        Err("Discovery 0 descriptor length is not a multiple of four")
    );
}

#[test]
fn rejects_duplicate_state_and_incompatible_discovery_major_version() {
    let mut bytes = DISCOVERY.to_vec();
    bytes[5] = 1;
    assert!(Discovery::parse(&bytes).is_err());
    bytes.copy_from_slice(DISCOVERY);
    bytes[64..66].copy_from_slice(&[0, 1]); // Second TPer descriptor.
    assert!(Discovery::parse(&bytes).is_err());
}

fn discovery_with_descriptors(descriptors: &[u8]) -> Vec<u8> {
    let mut response = DISCOVERY.to_vec();
    response.extend_from_slice(descriptors);
    let length = u32::try_from(response.len() - 4).unwrap();
    response[..4].copy_from_slice(&length.to_be_bytes());
    response
}

#[test]
fn decodes_block_sid_v1_and_v2_without_changing_the_other_fields() {
    let baseline = Discovery::parse(DISCOVERY).unwrap();
    assert!(
        serde_json::to_value(&baseline)
            .unwrap()
            .get("block_sid")
            .is_none()
    );

    for version in [1, 2] {
        for bits in 0..8 {
            let mut descriptor = [0; 16];
            descriptor[..6].copy_from_slice(&[0x04, 0x02, version << 4, 12, bits & 3, bits >> 2]);
            let mut discovery = Discovery::parse(&discovery_with_descriptors(&descriptor)).unwrap();
            let block_sid = discovery.block_sid.take().unwrap();
            assert_eq!(block_sid.descriptor_version, version);
            assert_eq!(block_sid.sid_matches_msid, bits & 1 == 0);
            assert_eq!(block_sid.sid_authentication_blocked, bits & 2 != 0);
            assert_eq!(block_sid.hardware_reset_can_clear_block, bits & 4 != 0);
            assert_eq!(discovery.feature_codes.pop(), Some(0x0402));
            assert_eq!(discovery, baseline);
        }
    }
}

#[test]
fn leaves_unknown_block_sid_versions_opaque_and_rejects_bad_known_descriptors() {
    let unknown = [0x04, 0x02, 0x30, 0x04, 0, 0, 0, 0];
    let response = Discovery::parse(&discovery_with_descriptors(&unknown)).unwrap();
    assert!(response.feature_codes.contains(&0x0402));
    assert!(response.block_sid.is_none());

    let mut truncated = unknown;
    truncated[2] = 0x10;
    assert_eq!(
        Discovery::parse(&discovery_with_descriptors(&truncated)),
        Err("truncated Block SID descriptor")
    );

    let mut duplicate = unknown.to_vec();
    duplicate.extend_from_slice(&unknown);
    assert_eq!(
        Discovery::parse(&discovery_with_descriptors(&duplicate)),
        Err("duplicate Discovery 0 descriptor")
    );
}
