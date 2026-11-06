// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(unsafe_code)]

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
use std::ptr::{from_mut, from_ref, null, null_mut};

use sedutil_rs::{
    discovery::Discovery,
    inquiry::{Inquiry, STANDARD_INQUIRY_LEN},
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::opal;
use windows_sys::Win32::{
    Storage::{
        FileSystem::{BusTypeUsb, FILE_SHARE_READ, FILE_SHARE_WRITE},
        IscsiDisc::{
            IOCTL_SCSI_PASS_THROUGH_DIRECT, SCSI_IOCTL_DATA_IN, SCSI_IOCTL_DATA_OUT,
            SCSI_PASS_THROUGH_DIRECT,
        },
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            DISK_ATTRIBUTE_OFFLINE, GET_DISK_ATTRIBUTES, IOCTL_DISK_GET_DISK_ATTRIBUTES,
            IOCTL_DISK_SET_DISK_ATTRIBUTES, IOCTL_DISK_UPDATE_PROPERTIES,
            IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, SET_DISK_ATTRIBUTES,
            STORAGE_ADAPTER_DESCRIPTOR, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_ID,
            STORAGE_PROPERTY_QUERY, StorageAdapterProperty, StorageDeviceProperty,
        },
    },
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const INQUIRY: [u8; 6] = [0x12, 0, 0, 0, STANDARD_INQUIRY_LEN as u8, 0];
// SECURITY PROTOCOL IN: TCG protocol 1, Discovery ComID 1, INC_512, four blocks.
const DISCOVERY_BLOCKS: u8 = 4;
const DISCOVERY_IN: [u8; 12] = [
    0xa2,
    0x01,
    0x00,
    0x01,
    0x80,
    0,
    0,
    0,
    0,
    DISCOVERY_BLOCKS,
    0,
    0,
];
const DISCOVERY_ALLOCATION: usize = DISCOVERY_BLOCKS as usize * 512;
const SENSE_CAPACITY: usize = 32;
const MAX_ALIGNMENT: usize = 65536;

#[repr(C)]
struct PassThrough {
    header: SCSI_PASS_THROUGH_DIRECT,
    _filler: u32,
    sense: [u8; SENSE_CAPACITY],
}

#[derive(Serialize)]
pub struct Report {
    schema_version: u8,
    device: String,
    bus: &'static str,
    vendor_id: String,
    product_id: String,
    firmware_revision: String,
    serial_number: Option<String>,
    legacy_scsi_salt_hex: String,
    discovery: Discovery,
}

struct Disk {
    device: File,
    alignment: usize,
    auto_unmount: bool,
}

#[derive(Serialize)]
pub struct AuthenticatedReport {
    #[serde(flatten)]
    inspection: Report,
    authority: &'static str,
    credential_profile: &'static str,
    session_mode: &'static str,
    lr0: opal::Lr0,
}

#[derive(Serialize)]
pub struct SetLr0Report {
    schema_version: u8,
    device: String,
    serial_number: String,
    authority: &'static str,
    credential_profile: &'static str,
    session_mode: &'static str,
    #[serde(flatten)]
    transition: opal::SetLr0Result,
}

struct Admin1Target {
    disk: Disk,
    inspection: Report,
    com_id: u16,
    salt: [u8; 20],
}

pub fn inspect(path: String) -> Result<Report> {
    let (_, report, _) = probe(path)?;
    Ok(report)
}

pub fn inspect_lr0(
    path: String,
    expected_serial: &str,
    compat_rw_session: bool,
) -> Result<AuthenticatedReport> {
    let Admin1Target {
        mut disk,
        inspection,
        com_id,
        salt,
    } = admin1_target(path, expected_serial)?;
    let password = prompt_admin1("Read LR0", &inspection.device, expected_serial)?;
    let lr0 = opal::read_lr0(
        &mut disk,
        com_id,
        std::process::id(),
        compat_rw_session,
        password,
        &salt,
    )?;
    Ok(AuthenticatedReport {
        inspection,
        authority: "Admin1",
        credential_profile: "legacy-scsi-salt",
        session_mode: if compat_rw_session {
            "read-write"
        } else {
            "read-only"
        },
        lr0,
    })
}

pub fn set_lr0(
    path: String,
    expected_serial: &str,
    locked: bool,
    manage_mount: bool,
) -> Result<SetLr0Report> {
    let Admin1Target {
        mut disk,
        inspection,
        com_id,
        salt,
    } = admin1_target(path, expected_serial)?;
    disk.auto_unmount = locked && manage_mount;
    if locked && !disk.auto_unmount {
        disk.require_offline()?;
    }
    let action = if disk.auto_unmount {
        "Take disk offline and lock LR0"
    } else if locked {
        "Lock LR0"
    } else {
        "Unlock LR0"
    };
    let password = prompt_admin1(action, &inspection.device, expected_serial)?;
    let transition = opal::set_lr0(
        &mut disk,
        com_id,
        std::process::id(),
        locked,
        password,
        &salt,
    )?;
    if !locked && manage_mount {
        disk.mount().map_err(|e| format!(
            "LR0 unlock verified, but Windows mount preparation failed: {e}. Check Windows disk state"
        ))?;
    }
    Ok(SetLr0Report {
        schema_version: 1,
        device: inspection.device,
        serial_number: expected_serial.to_owned(),
        authority: "Admin1",
        credential_profile: "legacy-scsi-salt",
        session_mode: "read-write",
        transition,
    })
}

fn admin1_target(path: String, expected_serial: &str) -> Result<Admin1Target> {
    let (disk, inspection, salt) = probe(path)?;
    if inspection.serial_number.as_deref() != Some(expected_serial) {
        return Err("disk serial does not match the selected device".into());
    }
    let discovery = &inspection.discovery;
    if !discovery.tper.as_ref().is_some_and(|tper| tper.sync)
        || !discovery
            .locking
            .as_ref()
            .is_some_and(|locking| locking.locking_supported && locking.locking_enabled)
    {
        return Err(
            "the drive does not advertise synchronous Opal locking with an active Locking SP"
                .into(),
        );
    }
    let com_id = discovery
        .opal_v2
        .as_ref()
        .filter(|opal| opal.base_com_id >= 0x1000 && opal.number_of_com_ids > 0)
        .ok_or("missing or invalid Opal v2 ComID")?
        .base_com_id;
    Ok(Admin1Target {
        disk,
        inspection,
        com_id,
        salt,
    })
}

fn prompt_admin1(action: &str, device: &str, serial: &str) -> Result<Zeroizing<String>> {
    let prompt = format!("{action}. Admin1 password for {device} (serial {serial}): ");
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn probe(path: String) -> Result<(Disk, Report, [u8; 20])> {
    // The SCSI pass-through IOCTL requires read/write access to the handle.
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)
        .map_err(|e| format!("opening {path}: {e}"))?;

    let descriptor = storage_property(&device, StorageDeviceProperty, "device descriptor")?;
    let bus = read_u32(&descriptor, offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType))?;
    if bus != BusTypeUsb as u32 {
        return Err(format!("expected a USB disk, Windows reported bus type {bus}").into());
    }
    let serial_number = serial_number(&descriptor)?;
    let adapter = storage_property(&device, StorageAdapterProperty, "adapter descriptor")?;
    let mask = read_u32(
        &adapter,
        offset_of!(STORAGE_ADAPTER_DESCRIPTOR, AlignmentMask),
    )?;
    let alignment = (mask as usize)
        .checked_add(1)
        .filter(|&n| n.is_power_of_two() && n <= MAX_ALIGNMENT)
        .ok_or("invalid storage adapter alignment mask")?;

    let inquiry = receive(&device, ReadCommand::Inquiry, alignment)?;
    let inquiry = Inquiry::parse(&inquiry)?;
    let discovery = receive(&device, ReadCommand::Discovery, alignment)?;
    let discovery = Discovery::parse(&discovery)?;

    let salt = inquiry.legacy_scsi_salt();
    let report = Report {
        schema_version: 1,
        device: path,
        bus: "USB",
        vendor_id: inquiry.vendor_id(),
        product_id: inquiry.product_id(),
        firmware_revision: inquiry.revision(),
        serial_number,
        legacy_scsi_salt_hex: salt.iter().map(|byte| format!("{byte:02x}")).collect(),
        discovery,
    };
    Ok((
        Disk {
            device,
            alignment,
            auto_unmount: false,
        },
        report,
        salt,
    ))
}

fn storage_property(device: &File, property: STORAGE_PROPERTY_ID, name: &str) -> Result<Vec<u8>> {
    // Two Win32 enum fields followed by the zeroed AdditionalParameters and padding.
    let query = [property, PropertyStandardQuery, 0];
    const _: () = assert!(size_of::<[i32; 3]>() == size_of::<STORAGE_PROPERTY_QUERY>());
    let mut data = vec![0u8; 4096];
    let mut returned = 0;
    // SAFETY: the handle is valid for the duration of the synchronous call.
    // The input and output pointers address separate, live buffers of the supplied sizes.
    let ok = unsafe {
        DeviceIoControl(
            device.as_raw_handle(),
            IOCTL_STORAGE_QUERY_PROPERTY,
            from_ref(&query).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            data.as_mut_ptr().cast(),
            data.len() as u32,
            &mut returned,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!("reading {name}: {}", io::Error::last_os_error()).into());
    }

    let actual = data
        .get(..returned as usize)
        .ok_or("invalid descriptor transfer length")?;
    let declared = read_u32(actual, 4)? as usize; // STORAGE_DESCRIPTOR_HEADER.Size
    if !(8..=actual.len()).contains(&declared) {
        return Err(
            format!("incomplete {name}: {declared} bytes declared, {returned} returned").into(),
        );
    }
    data.truncate(declared);
    Ok(data)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..)
        .and_then(<[u8]>::first_chunk::<4>)
        .ok_or("truncated Windows storage descriptor")?;
    Ok(u32::from_le_bytes(*bytes))
}

fn serial_number(descriptor: &[u8]) -> Result<Option<String>> {
    let offset = read_u32(
        descriptor,
        offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset),
    )? as usize;
    if offset == 0 {
        return Ok(None);
    }
    let field = descriptor
        .get(offset..)
        .filter(|_| offset >= offset_of!(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties))
        .ok_or("invalid Windows storage serial number offset")?;
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .ok_or("unterminated Windows storage serial number")?;
    let serial = String::from_utf8_lossy(&field[..end]).trim().to_owned();
    Ok((!serial.is_empty()).then_some(serial))
}

#[derive(Clone, Copy)]
enum ReadCommand {
    Inquiry,
    Discovery,
}

impl ReadCommand {
    fn parts(self) -> (&'static str, &'static [u8], usize) {
        match self {
            Self::Inquiry => ("SCSI INQUIRY", &INQUIRY, STANDARD_INQUIRY_LEN),
            Self::Discovery => ("Opal Discovery 0", &DISCOVERY_IN, DISCOVERY_ALLOCATION),
        }
    }
}

fn receive(device: &File, command: ReadCommand, alignment: usize) -> Result<Vec<u8>> {
    let (name, cdb, length) = command.parts();
    transfer(device, name, cdb, length, alignment, None)
}

impl Disk {
    fn is_offline(&self) -> Result<bool> {
        const ATTRIBUTES_SIZE: u32 = size_of::<GET_DISK_ATTRIBUTES>() as u32;
        let mut attributes = GET_DISK_ATTRIBUTES::default();
        let mut returned = 0;
        // SAFETY: the handle and writable output pointers remain valid during the
        // synchronous call. This IOCTL takes no input buffer.
        let ok = unsafe {
            DeviceIoControl(
                self.device.as_raw_handle(),
                IOCTL_DISK_GET_DISK_ATTRIBUTES,
                null(),
                0,
                from_mut(&mut attributes).cast(),
                ATTRIBUTES_SIZE,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            return Err(format!("cannot verify Windows disk offline state: {error}").into());
        }
        parse_offline_attributes(attributes, returned)
    }

    fn require_offline(&self) -> Result<()> {
        if !self.is_offline()? {
            return Err("lock-lr0 requires the target disk to be offline in Windows".into());
        }
        Ok(())
    }

    fn set_offline(&self, offline: bool) -> Result<()> {
        if self.is_offline()? == offline {
            return Ok(());
        }
        let attributes = SET_DISK_ATTRIBUTES {
            Version: size_of::<SET_DISK_ATTRIBUTES>() as u32,
            Attributes: if offline { DISK_ATTRIBUTE_OFFLINE } else { 0 },
            AttributesMask: DISK_ATTRIBUTE_OFFLINE,
            ..Default::default()
        };
        self.disk_control(IOCTL_DISK_SET_DISK_ATTRIBUTES, Some(&attributes))
            .map_err(|e| format!("changing Windows disk offline state: {e}"))?;
        if self.is_offline()? != offline {
            return Err("Windows did not confirm the requested disk offline state".into());
        }
        Ok(())
    }

    fn mount(&self) -> Result<()> {
        self.set_offline(false)?;
        self.disk_control(IOCTL_DISK_UPDATE_PROPERTIES, None)
            .map_err(|e| format!("refreshing Windows partition information: {e}"))?;
        Ok(())
    }

    fn disk_control(&self, code: u32, attributes: Option<&SET_DISK_ATTRIBUTES>) -> io::Result<()> {
        let (input, input_size) = attributes.map_or((null(), 0), |value| {
            (
                from_ref(value).cast(),
                size_of::<SET_DISK_ATTRIBUTES>() as u32,
            )
        });
        let mut returned = 0;
        // SAFETY: the handle and optional input buffer stay live during the
        // synchronous call. Neither control code takes an output buffer.
        let ok = unsafe {
            DeviceIoControl(
                self.device.as_raw_handle(),
                code,
                input,
                input_size,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl opal::Transport for Disk {
    fn prepare_lock(&self) -> Result<()> {
        if self.auto_unmount {
            self.set_offline(true)
        } else {
            self.require_offline()
        }
    }

    fn send(&mut self, com_id: u16, data: &[u8; opal::OUT_LEN]) -> opal::Result<()> {
        let cdb = security_protocol_cdb(0xb5, com_id, 1);
        transfer(
            &self.device,
            "Opal Security Protocol Out",
            &cdb,
            data.len(),
            self.alignment,
            Some(data),
        )?;
        Ok(())
    }

    fn receive(&mut self, com_id: u16) -> opal::Result<Vec<u8>> {
        let cdb = security_protocol_cdb(0xa2, com_id, 4);
        transfer(
            &self.device,
            "Opal Security Protocol In",
            &cdb,
            opal::IN_LEN,
            self.alignment,
            None,
        )
    }
}

fn parse_offline_attributes(attributes: GET_DISK_ATTRIBUTES, returned: u32) -> Result<bool> {
    let size = size_of::<GET_DISK_ATTRIBUTES>() as u32;
    if returned != size || attributes.Version != size {
        return Err("cannot verify Windows disk offline state: invalid disk attributes".into());
    }
    Ok(attributes.Attributes & DISK_ATTRIBUTE_OFFLINE != 0)
}

fn security_protocol_cdb(opcode: u8, com_id: u16, blocks: u8) -> [u8; 12] {
    let [hi, lo] = com_id.to_be_bytes();
    [opcode, 1, hi, lo, 0x80, 0, 0, 0, 0, blocks, 0, 0]
}

fn transfer(
    device: &File,
    name: &str,
    cdb: &[u8],
    length: usize,
    alignment: usize,
    outbound: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut storage = Zeroizing::new(vec![0u8; length + alignment - 1]);
    let start = storage.as_ptr().align_offset(alignment);
    let data = start
        .checked_add(length)
        .and_then(|end| storage.get_mut(start..end))
        .ok_or("unable to align SCSI transfer buffer")?;

    let direction = match outbound {
        Some(payload) => {
            data.copy_from_slice(payload);
            SCSI_IOCTL_DATA_OUT
        }
        None => SCSI_IOCTL_DATA_IN,
    };

    let sense_offset = offset_of!(PassThrough, sense);
    let header_len = size_of::<SCSI_PASS_THROUGH_DIRECT>();
    let mut request = PassThrough {
        header: SCSI_PASS_THROUGH_DIRECT {
            Length: header_len as u16,
            CdbLength: cdb.len() as u8,
            SenseInfoLength: SENSE_CAPACITY as u8,
            DataIn: direction as u8,
            DataTransferLength: length as u32,
            TimeOutValue: 10,
            DataBuffer: data.as_mut_ptr().cast(),
            SenseInfoOffset: sense_offset as u32,
            ..Default::default()
        },
        _filler: 0,
        sense: [0; SENSE_CAPACITY],
    };
    request.header.Cdb[..cdb.len()].copy_from_slice(cdb);
    let buffer = (&raw mut request).cast();
    let buffer_len = size_of::<PassThrough>() as u32;
    let mut returned = 0;

    // SAFETY: PassThrough has the Win32 layout with an in-bounds sense buffer.
    // Its shared input/output pointer and the aligned, writable DataBuffer
    // stay live until this synchronous IOCTL completes.
    let ok = unsafe {
        DeviceIoControl(
            device.as_raw_handle(),
            IOCTL_SCSI_PASS_THROUGH_DIRECT,
            buffer,
            buffer_len,
            buffer,
            buffer_len,
            &mut returned,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "{name}: Windows transport error: {}",
            io::Error::last_os_error()
        )
        .into());
    }
    if !(header_len..=buffer_len as usize).contains(&(returned as usize)) {
        return Err(format!("{name}: invalid Windows pass-through response length").into());
    }

    if request.header.ScsiStatus != 0 {
        let sense_len = usize::from(request.header.SenseInfoLength)
            .min(request.sense.len())
            .min((returned as usize).saturating_sub(sense_offset));
        let mut detail = format!("{name}: SCSI status 0x{:02x}", request.header.ScsiStatus);
        if request.header.SenseInfoOffset as usize == sense_offset
            && let Some((key, asc, ascq)) = sense_code(&request.sense[..sense_len])
        {
            use std::fmt::Write as _;
            write!(
                &mut detail,
                " (sense key 0x{key:02x}, ASC/ASCQ {asc:02x}/{ascq:02x})"
            )?;
        }
        return Err(detail.into());
    }

    let transferred = request.header.DataTransferLength as usize;
    if outbound.is_some() {
        if transferred != length {
            return Err("incomplete SCSI data-out transfer".into());
        }
        return Ok(Vec::new());
    }
    let received = data
        .get(..transferred)
        .ok_or("invalid SCSI data transfer length")?;
    Ok(received.to_vec())
}

fn sense_code(sense: &[u8]) -> Option<(u8, u8, u8)> {
    match sense.first()? & 0x7f {
        0x70 | 0x71 => {
            let fixed = sense.first_chunk::<14>()?;
            (fixed[7] >= 6).then_some((fixed[2] & 0x0f, fixed[12], fixed[13]))
        }
        0x72 | 0x73 => {
            let descriptor = sense.first_chunk::<8>()?;
            Some((descriptor[1] & 0x0f, descriptor[2], descriptor[3]))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_state_distinguishes_online_and_rejects_malformed_attributes() {
        let size = size_of::<GET_DISK_ATTRIBUTES>() as u32;
        let offline = GET_DISK_ATTRIBUTES {
            Version: size,
            Attributes: DISK_ATTRIBUTE_OFFLINE,
            ..Default::default()
        };
        assert!(parse_offline_attributes(offline, size).unwrap());
        assert!(parse_offline_attributes(offline, size - 1).is_err());
        assert!(
            parse_offline_attributes(
                GET_DISK_ATTRIBUTES {
                    Version: 0,
                    ..offline
                },
                size
            )
            .is_err()
        );
        let read_only = GET_DISK_ATTRIBUTES {
            Attributes: windows_sys::Win32::System::Ioctl::DISK_ATTRIBUTE_READ_ONLY,
            ..offline
        };
        assert!(!parse_offline_attributes(read_only, size).unwrap());
    }

    #[test]
    fn read_commands_match_the_reference_transport() {
        assert_eq!(INQUIRY, [0x12, 0, 0, 0, 36, 0]);
        assert_eq!(DISCOVERY_IN, [0xa2, 1, 0, 1, 0x80, 0, 0, 0, 0, 4, 0, 0]);
        assert_eq!(DISCOVERY_ALLOCATION, 2048);
    }

    #[test]
    fn session_cdbs_use_protocol_one_and_the_selected_com_id() {
        assert_eq!(
            security_protocol_cdb(0xb5, 0x1004, 1),
            [0xb5, 1, 0x10, 4, 0x80, 0, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(
            security_protocol_cdb(0xa2, 0x1004, 4),
            [0xa2, 1, 0x10, 4, 0x80, 0, 0, 0, 0, 4, 0, 0]
        );
    }

    #[test]
    fn serial_number_is_bounded_by_the_returned_device_descriptor() {
        let offset_field = offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset);
        let property_start = offset_of!(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties);
        let mut descriptor = vec![0; property_start + 5];
        assert_eq!(serial_number(&descriptor).unwrap(), None);

        descriptor[offset_field..offset_field + 4]
            .copy_from_slice(&(property_start as u32).to_le_bytes());
        descriptor[property_start..].copy_from_slice(b"T7-1\0");
        assert_eq!(serial_number(&descriptor).unwrap().as_deref(), Some("T7-1"));
        assert!(serial_number(&descriptor[..descriptor.len() - 1]).is_err());

        descriptor[offset_field..offset_field + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(serial_number(&descriptor).is_err());
    }

    #[test]
    fn sense_decoding_checks_actual_and_declared_lengths() {
        let mut fixed = [0; 14];
        fixed[0] = 0x70;
        fixed[2] = 0x05;
        fixed[7] = 6;
        fixed[12] = 0x20;
        assert_eq!(sense_code(&fixed), Some((5, 0x20, 0)));
        assert_eq!(sense_code(&fixed[..13]), None);
        fixed[7] = 0;
        assert_eq!(sense_code(&fixed), None);
        assert_eq!(
            sense_code(&[0x72, 0x05, 0x20, 0, 0, 0, 0, 0]),
            Some((5, 0x20, 0))
        );
    }
}
