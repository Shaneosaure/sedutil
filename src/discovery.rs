// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;

const HEADER_LEN: usize = 48;
const TPER: u16 = 0x0001;
const LOCKING: u16 = 0x0002;
const OPAL_V2: u16 = 0x0203;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Discovery {
    pub major_version: u16,
    pub minor_version: u16,
    pub feature_codes: Vec<u16>,
    pub tper: Option<Tper>,
    pub locking: Option<Locking>,
    pub opal_v2: Option<OpalV2>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Tper {
    pub sync: bool,
    pub async_supported: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Locking {
    pub locking_supported: bool,
    pub locking_enabled: bool,
    pub locked: bool,
    pub media_encryption: bool,
    pub mbr_enabled: bool,
    pub mbr_done: bool,
    pub mbr_shadowing_not_supported: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct OpalV2 {
    pub descriptor_version: u8,
    pub ssc_minor_version: u8,
    pub base_com_id: u16,
    pub number_of_com_ids: u16,
}

impl Discovery {
    /// Decode TCG Core 2.01 §3.3.6. Padding after the declared response
    /// belongs to the transport and is outside the descriptor stream.
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let (header, _) = data
            .split_first_chunk::<HEADER_LEN>()
            .ok_or("truncated Discovery 0 header")?;
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let end = (length as usize)
            .checked_add(4)
            .ok_or("Discovery 0 length overflows")?;
        let mut descriptors = data
            .get(HEADER_LEN..end)
            .ok_or("Discovery 0 length does not fit the received response")?;
        let major_version = u16::from_be_bytes([header[4], header[5]]);
        if major_version != 0 {
            return Err("unsupported Discovery 0 major version");
        }

        let mut discovery = Self {
            major_version,
            minor_version: u16::from_be_bytes([header[6], header[7]]),
            feature_codes: Vec::new(),
            tper: None,
            locking: None,
            opal_v2: None,
        };
        while !descriptors.is_empty() {
            let (descriptor, rest) = descriptors
                .split_first_chunk::<4>()
                .ok_or("truncated Discovery 0 descriptor header")?;
            let code = u16::from_be_bytes([descriptor[0], descriptor[1]]);
            let body_len = usize::from(descriptor[3]);
            if !body_len.is_multiple_of(4) {
                return Err("Discovery 0 descriptor length is not a multiple of four");
            }
            let (body, tail) = rest
                .split_at_checked(body_len)
                .ok_or("truncated Discovery 0 descriptor body")?;
            match code {
                TPER => set_once(&mut discovery.tper, Tper::parse(body)?)?,
                LOCKING => set_once(&mut discovery.locking, Locking::parse(body)?)?,
                OPAL_V2 => set_once(&mut discovery.opal_v2, OpalV2::parse(descriptor[2], body)?)?,
                _ => {}
            }
            discovery.feature_codes.push(code);
            descriptors = tail;
        }
        Ok(discovery)
    }
}

impl Tper {
    fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let (body, _) = data
            .split_first_chunk::<12>()
            .ok_or("truncated TPer descriptor")?;
        Ok(Self {
            sync: body[0] & 0x01 != 0,
            async_supported: body[0] & 0x02 != 0,
        })
    }
}

impl Locking {
    fn parse(data: &[u8]) -> Result<Self, &'static str> {
        let (body, _) = data
            .split_first_chunk::<12>()
            .ok_or("truncated Locking descriptor")?;
        let flags = body[0];
        Ok(Self {
            locking_supported: flags & 0x01 != 0,
            locking_enabled: flags & 0x02 != 0,
            locked: flags & 0x04 != 0,
            media_encryption: flags & 0x08 != 0,
            mbr_enabled: flags & 0x10 != 0,
            mbr_done: flags & 0x20 != 0,
            mbr_shadowing_not_supported: flags & 0x40 != 0,
        })
    }
}

impl OpalV2 {
    fn parse(version: u8, data: &[u8]) -> Result<Self, &'static str> {
        let (body, _) = data
            .split_first_chunk::<16>()
            .ok_or("truncated Opal V2 descriptor")?;
        Ok(Self {
            descriptor_version: version >> 4,
            ssc_minor_version: version & 0x0f,
            base_com_id: u16::from_be_bytes([body[0], body[1]]),
            number_of_com_ids: u16::from_be_bytes([body[2], body[3]]),
        })
    }
}

fn set_once<T>(target: &mut Option<T>, value: T) -> Result<(), &'static str> {
    if target.is_some() {
        return Err("duplicate Discovery 0 descriptor");
    }
    *target = Some(value);
    Ok(())
}
