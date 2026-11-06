// SPDX-License-Identifier: GPL-3.0-or-later

pub const STANDARD_INQUIRY_LEN: usize = 36;

#[derive(Debug, PartialEq, Eq)]
pub struct Inquiry<'a> {
    vendor_id: &'a [u8; 8],
    product_id: &'a [u8],
    revision: &'a [u8],
}

impl<'a> Inquiry<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, &'static str> {
        let (standard, _) = data
            .split_first_chunk::<STANDARD_INQUIRY_LEN>()
            .ok_or("truncated standard SCSI INQUIRY response")?;
        if standard[0] != 0 {
            return Err("SCSI INQUIRY did not identify a connected direct-access device");
        }
        if usize::from(standard[4]) < STANDARD_INQUIRY_LEN - 5 {
            return Err("SCSI INQUIRY advertises an incomplete standard response");
        }

        Ok(Self {
            vendor_id: standard[8..16].as_array().expect("fixed-width vendor ID"),
            product_id: &standard[16..32],
            revision: &standard[32..36],
        })
    }

    pub fn vendor_id(&self) -> String {
        display_field(self.vendor_id)
    }

    pub fn product_id(&self) -> String {
        display_field(self.product_id)
    }

    pub fn revision(&self) -> String {
        display_field(self.revision)
    }

    /// The salt layout used by sedutil 1.20.0's Linux SCSI path.
    pub fn legacy_scsi_salt(&self) -> [u8; 20] {
        let mut salt = [0; 20];
        salt[..8].copy_from_slice(self.vendor_id);
        salt
    }
}

fn display_field(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches([' ', '\0'])
        .to_owned()
}
