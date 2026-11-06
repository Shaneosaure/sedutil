// SPDX-License-Identifier: GPL-3.0-or-later
#![forbid(unsafe_code)]

use std::{
    error::Error,
    thread,
    time::{Duration, Instant},
};

use hmac::Hmac;
use pbkdf2::pbkdf2;
use serde::Serialize;
use sha1::Sha1;
use zeroize::Zeroizing;

pub(super) type Result<T> = std::result::Result<T, Box<dyn Error>>;

const SM: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0xff];
const START_SESSION: [u8; 8] = [0, 0, 0, 0, 0, 0, 0xff, 2];
const SYNC_SESSION: [u8; 8] = [0, 0, 0, 0, 0, 0, 0xff, 3];
const LOCKING_SP: [u8; 8] = [0, 0, 2, 5, 0, 0, 0, 2];
const ADMIN1: [u8; 8] = [0, 0, 0, 9, 0, 1, 0, 1];
const LR0: [u8; 8] = [0, 0, 8, 2, 0, 0, 0, 1];
const GET: [u8; 8] = [0, 0, 0, 6, 0, 0, 0, 0x16];

const LIST: u8 = 0xf0;
const END_LIST: u8 = 0xf1;
const NAME: u8 = 0xf2;
const END_NAME: u8 = 0xf3;
const CALL: u8 = 0xf8;
const END_DATA: u8 = 0xf9;
const END_SESSION: u8 = 0xfa;
const STATUS_TRAILER: [u8; 6] = [END_DATA, LIST, 0, 0, 0, END_LIST];

const COM_HEADER: usize = 20;
const PACKET_HEADER: usize = 24;
const SUB_HEADER: usize = 12;
const HEADER: usize = COM_HEADER + PACKET_HEADER + SUB_HEADER;
pub(super) const OUT_LEN: usize = 512;
pub(super) const IN_LEN: usize = 2048;

pub(super) trait Transport {
    fn send(&mut self, com_id: u16, data: &[u8; OUT_LEN]) -> Result<()>;
    fn receive(&mut self, com_id: u16) -> Result<Vec<u8>>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Session {
    host: u32,
    tper: u32,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(super) struct Lr0 {
    range_start: u64,
    range_length: u64,
    read_lock_enabled: bool,
    write_lock_enabled: bool,
    read_locked: bool,
    write_locked: bool,
}

pub(super) fn read_lr0(
    transport: &mut impl Transport,
    com_id: u16,
    host: u32,
    compat_rw_session: bool,
    password: Zeroizing<String>,
    salt: &[u8; 20],
) -> Result<Lr0> {
    // The legacy C++ profile hashes at most 256 bytes. Reject longer input
    // explicitly so a typo cannot silently authenticate a truncated secret.
    if password.is_empty() || password.len() > 256 || password.as_bytes().contains(&0) {
        return Err("Admin1 password must contain 1–256 UTF-8 bytes without NUL".into());
    }

    let mut challenge = Zeroizing::new([0; 32]);
    pbkdf2::<Hmac<Sha1>>(password.as_bytes(), salt, 75_000, &mut *challenge)
        .map_err(|_| "unable to initialize the legacy Admin1 derivation")?;
    drop(password);
    let request = start_session(com_id, host, compat_rw_session, &challenge);
    drop(challenge);
    transport
        .send(com_id, &request)
        .map_err(|e| format!("StartSession send: {e}"))?;
    drop(request);

    let response = receive(transport, com_id).map_err(|e| format!("SyncSession receive: {e}"))?;
    let session = sync_session(packet_payload(&response, com_id, Session::default())?, host)?;

    let request = get_lr0(com_id, session);
    // A failed transfer may have left a reply pending. Do not send another
    // method if the transaction did not return a matching complete packet.
    transport
        .send(com_id, &request)
        .map_err(|e| format!("GET LR0 send: {e}"))?;
    let response = receive(transport, com_id).map_err(|e| format!("GET LR0 receive: {e}"))?;
    let values = parse_lr0(packet_payload(&response, com_id, session)?);

    let close = close_session(transport, com_id, session);
    match (values, close) {
        (Ok(values), Ok(())) => Ok(values),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(close_error)) => Err(format!("{error}. {close_error}").into()),
    }
}

fn close_session(transport: &mut impl Transport, com_id: u16, session: Session) -> Result<()> {
    let request = frame(com_id, session, &[END_SESSION]);
    transport
        .send(com_id, &request)
        .map_err(|e| format!("EndSession send: {e}"))?;
    let response = receive(transport, com_id).map_err(|e| format!("EndSession receive: {e}"))?;
    if packet_payload(&response, com_id, session)? != [END_SESSION] {
        return Err("invalid EndSession acknowledgement".into());
    }
    Ok(())
}

// Poll IF-RECV only. An OUT request, including StartSession, is never retried.
fn receive(transport: &mut impl Transport, com_id: u16) -> Result<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        thread::sleep(Duration::from_millis(25));
        let reply = Zeroizing::new(transport.receive(com_id)?);
        if reply.len() > IN_LEN {
            return Err("oversized Opal transport response".into());
        }
        let header = com_header(&reply, com_id)?;
        let pending = header[8..12] == 1u32.to_be_bytes() && header[12..20] == [0; 8];
        if !pending {
            return Ok(reply);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for the TPer response".into());
        }
    }
}

fn start_session(
    com_id: u16,
    host: u32,
    compat_rw_session: bool,
    challenge: &[u8; 32],
) -> Zeroizing<[u8; OUT_LEN]> {
    // Sized to prevent reallocation while the authentication material is present.
    let mut args = Zeroizing::new(Vec::with_capacity(96));
    call(&mut args, SM, START_SESSION);
    args.extend_from_slice(&[LIST, 0x84]);
    args.extend_from_slice(&host.to_be_bytes());
    uid(&mut args, LOCKING_SP);
    args.extend_from_slice(&[u8::from(compat_rw_session), NAME, 0, 0xd0, 32]); // Write, HostChallenge
    args.extend_from_slice(challenge);
    args.extend_from_slice(&[END_NAME, NAME, 3]); // HostSigningAuthority
    uid(&mut args, ADMIN1);
    args.extend_from_slice(&[END_NAME, END_LIST]);
    args.extend_from_slice(&STATUS_TRAILER);
    frame(com_id, Session::default(), &args)
}

fn get_lr0(com_id: u16, session: Session) -> Zeroizing<[u8; OUT_LEN]> {
    let mut args = Vec::new();
    call(&mut args, LR0, GET);
    args.extend_from_slice(&[
        LIST, LIST, NAME, 3, 3, END_NAME, NAME, 4, 8, END_NAME, END_LIST, END_LIST,
    ]);
    args.extend_from_slice(&STATUS_TRAILER);
    frame(com_id, session, &args)
}

fn call(args: &mut Vec<u8>, invoking: [u8; 8], method: [u8; 8]) {
    args.push(CALL);
    uid(args, invoking);
    uid(args, method);
}

fn uid(args: &mut Vec<u8>, value: [u8; 8]) {
    args.push(0xa8);
    args.extend_from_slice(&value);
}

fn frame(com_id: u16, session: Session, payload: &[u8]) -> Zeroizing<[u8; OUT_LEN]> {
    let mut frame = Zeroizing::new([0; OUT_LEN]);
    let len = payload.len().next_multiple_of(4);
    frame[4..6].copy_from_slice(&com_id.to_be_bytes());
    frame[16..20].copy_from_slice(&((PACKET_HEADER + SUB_HEADER + len) as u32).to_be_bytes());
    frame[20..24].copy_from_slice(&session.tper.to_be_bytes());
    frame[24..28].copy_from_slice(&session.host.to_be_bytes());
    frame[40..44].copy_from_slice(&((SUB_HEADER + len) as u32).to_be_bytes());
    frame[52..56].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    frame[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    frame
}

fn com_header(reply: &[u8], com_id: u16) -> Result<&[u8; COM_HEADER]> {
    let header = reply
        .first_chunk::<COM_HEADER>()
        .ok_or("truncated ComPacket header")?;
    if header[4..6] != com_id.to_be_bytes() || header[6..8] != [0, 0] {
        return Err("unexpected ComID or ComID extension".into());
    }
    Ok(header)
}

fn packet_payload(reply: &[u8], com_id: u16, session: Session) -> Result<&[u8]> {
    let com = com_header(reply, com_id)?;
    if com[8..16] != [0; 8] {
        return Err("incomplete or oversized Opal response".into());
    }
    let com_len = u32::from_be_bytes([com[16], com[17], com[18], com[19]]) as usize;
    let packet = reply[COM_HEADER..]
        .get(..com_len)
        .ok_or("truncated ComPacket")?;
    let (header, sub) = packet
        .split_first_chunk::<PACKET_HEADER>()
        .ok_or("truncated Packet header")?;
    if header[..4] != session.tper.to_be_bytes() || header[4..8] != session.host.to_be_bytes() {
        return Err("response session does not match the request".into());
    }
    let packet_len = u32::from_be_bytes([header[20], header[21], header[22], header[23]]) as usize;
    if packet_len != sub.len() {
        return Err("invalid Packet length or multiple Packets".into());
    }
    let (header, body) = sub
        .split_first_chunk::<SUB_HEADER>()
        .ok_or("truncated SubPacket header")?;
    if header[6..8] != [0, 0] {
        return Err("expected an Opal data SubPacket".into());
    }
    let len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    let payload = body
        .get(..len)
        .filter(|p| !p.is_empty())
        .ok_or("invalid SubPacket length")?;
    if len.next_multiple_of(4) != body.len() {
        return Err("invalid SubPacket padding or multiple SubPackets".into());
    }
    Ok(payload)
}

struct Tokens<'a>(&'a [u8]);

impl<'a> Tokens<'a> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(len).ok_or("truncated Opal token")?;
        self.0 = rest;
        Ok(value)
    }

    fn expect(&mut self, token: u8) -> Result<()> {
        if self.take(1)? != [token] {
            return Err("unexpected Opal control token".into());
        }
        Ok(())
    }

    fn atom(&mut self) -> Result<(bool, &'a [u8])> {
        let head = self.take(1)?[0];
        let (is_bytes, signed_or_continued, len) = match head {
            0x80..=0xbf => (head & 0x20 != 0, head & 0x10 != 0, usize::from(head & 0x0f)),
            0xc0..=0xdf => (
                head & 0x10 != 0,
                head & 8 != 0,
                (usize::from(head & 7) << 8) | usize::from(self.take(1)?[0]),
            ),
            0xe0..=0xe3 => {
                let len = self.take(3)?;
                (
                    head & 2 != 0,
                    head & 1 != 0,
                    usize::from(len[0]) << 16 | usize::from(len[1]) << 8 | usize::from(len[2]),
                )
            }
            _ => return Err("unsupported Opal atom".into()),
        };
        if signed_or_continued {
            return Err("signed or continued Opal atom".into());
        }
        Ok((is_bytes, self.take(len)?))
    }

    fn uint(&mut self) -> Result<u64> {
        if let Some(value @ 0..=0x3f) = self.peek() {
            self.take(1)?;
            return Ok(u64::from(value));
        }
        let (bytes, value) = self.atom()?;
        if bytes || value.is_empty() || value.len() > 8 {
            return Err("invalid Opal unsigned integer".into());
        }
        Ok(value
            .iter()
            .fold(0, |acc, &byte| (acc << 8) | u64::from(byte)))
    }

    fn uid(&mut self, expected: [u8; 8]) -> Result<()> {
        let (is_bytes, bytes) = self.atom()?;
        if !is_bytes || bytes != expected {
            return Err("unexpected Opal UID".into());
        }
        Ok(())
    }
}

fn method_body<'a>(payload: &'a [u8], stage: &str) -> Result<Tokens<'a>> {
    // EndData can occur inside a byte string, so identify the trailer only
    // while walking tokens. Its three elements are unsigned atoms.
    let mut scan = Tokens(payload);
    let body_len = loop {
        match scan.peek() {
            Some(END_DATA) => break payload.len() - scan.0.len(),
            Some(0..=0x3f | LIST | END_LIST | NAME | END_NAME | CALL | 0xff) => {
                scan.take(1)?;
            }
            Some(0x80..=0xe3) => {
                scan.atom()?;
            }
            _ => return Err("missing or invalid Opal method status trailer".into()),
        }
    };
    scan.expect(END_DATA)?;
    scan.expect(LIST)?;
    let status = scan.uint()?;
    if scan.uint()? != 0 || scan.uint()? != 0 {
        return Err("invalid reserved Opal method status values".into());
    }
    scan.expect(END_LIST)?;
    if !scan.0.is_empty() {
        return Err("unexpected tokens after Opal method status".into());
    }
    match status {
        0 => Ok(Tokens(&payload[..body_len])),
        1 => Err(format!("{stage}: NOT_AUTHORIZED (0x01)").into()),
        0x0c => Err(format!("{stage}: INVALID_PARAMETER (0x0c)").into()),
        0x12 => Err(format!("{stage}: AUTHORITY_LOCKED_OUT (0x12)").into()),
        _ => Err(format!("{stage}: Opal method status 0x{status:02x}").into()),
    }
}

fn sync_session(payload: &[u8], host: u32) -> Result<Session> {
    let mut tokens = method_body(payload, "StartSession")?;
    tokens.expect(CALL)?;
    tokens.uid(SM)?;
    tokens.uid(SYNC_SESSION)?;
    tokens.expect(LIST)?;
    if tokens.uint()? != u64::from(host) {
        return Err("SyncSession echoed an unexpected host session number".into());
    }
    let tper = u32::try_from(tokens.uint()?)?;
    if tper == 0 {
        return Err("SyncSession returned a zero TPer session number".into());
    }
    while tokens.peek() == Some(NAME) {
        tokens.expect(NAME)?;
        tokens.uint()?;
        match tokens.peek() {
            Some(0..=0x3f) => {
                tokens.uint()?;
            }
            _ => {
                tokens.atom()?;
            }
        }
        tokens.expect(END_NAME)?;
    }
    tokens.expect(END_LIST)?;
    if !tokens.0.is_empty() {
        return Err("unexpected SyncSession tokens".into());
    }
    Ok(Session { host, tper })
}

fn parse_lr0(payload: &[u8]) -> Result<Lr0> {
    let mut tokens = method_body(payload, "GET LR0")?;
    tokens.expect(LIST)?;
    tokens.expect(LIST)?;
    let mut columns = [None; 6];
    while tokens.peek() == Some(NAME) {
        tokens.expect(NAME)?;
        let column = tokens.uint()?;
        if !(3..=8).contains(&column) {
            return Err("unexpected LR0 column".into());
        }
        let target = &mut columns[(column - 3) as usize];
        if target.is_some() {
            return Err("duplicate LR0 column".into());
        }
        *target = Some(tokens.uint()?);
        tokens.expect(END_NAME)?;
    }
    tokens.expect(END_LIST)?;
    tokens.expect(END_LIST)?;
    if !tokens.0.is_empty() {
        return Err("unexpected GET LR0 tokens".into());
    }
    let [
        Some(range_start),
        Some(range_length),
        Some(read_enable @ 0..=1),
        Some(write_enable @ 0..=1),
        Some(read_locked @ 0..=1),
        Some(write_locked @ 0..=1),
    ] = columns
    else {
        return Err("missing or invalid LR0 column values".into());
    };
    Ok(Lr0 {
        range_start,
        range_length,
        read_lock_enabled: read_enable == 1,
        write_lock_enabled: write_enable == 1,
        read_locked: read_locked == 1,
        write_locked: write_locked == 1,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    const COM_ID: u16 = 0x1004;
    const HOST: u32 = 105;
    const SESSION: Session = Session {
        host: HOST,
        tper: 0x1234,
    };
    const SALT: [u8; 20] = *b"Samsung \0\0\0\0\0\0\0\0\0\0\0\0";

    fn sync_reply(host: u8) -> Vec<u8> {
        let mut payload = vec![
            0xf8, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xa8, 0, 0, 0, 0, 0, 0, 0xff, 3, 0xf0, 0x81,
            host, 0x82, 0x12, 0x34, 0xf1,
        ];
        payload.extend_from_slice(&STATUS_TRAILER);
        frame(COM_ID, Session::default(), &payload).to_vec()
    }

    fn lr0_reply() -> Vec<u8> {
        let payload = [
            0xf0, 0xf0, 0xf2, 3, 0, 0xf3, 0xf2, 4, 0x85, 1, 0, 0, 0, 1, 0xf3, 0xf2, 5, 1, 0xf3,
            0xf2, 6, 1, 0xf3, 0xf2, 7, 1, 0xf3, 0xf2, 8, 0, 0xf3, 0xf1, 0xf1, 0xf9, 0xf0, 0, 0, 0,
            0xf1,
        ];
        frame(COM_ID, SESSION, &payload).to_vec()
    }

    #[derive(Default)]
    struct Sim {
        received: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Transport for Sim {
        fn send(&mut self, com_id: u16, data: &[u8; OUT_LEN]) -> Result<()> {
            assert_eq!(com_id, COM_ID);
            self.sent.push(data.to_vec());
            Ok(())
        }

        fn receive(&mut self, com_id: u16) -> Result<Vec<u8>> {
            assert_eq!(com_id, COM_ID);
            self.received
                .pop_front()
                .ok_or_else(|| "simulated read failure".into())
        }
    }

    fn test_read(sim: &mut Sim) -> Result<Lr0> {
        read_lr0(
            sim,
            COM_ID,
            HOST,
            false,
            Zeroizing::new("password".into()),
            &SALT,
        )
    }

    #[test]
    fn opens_read_only_session_reads_lr0_and_closes_it() {
        let mut pending = vec![0; COM_HEADER];
        pending[4..6].copy_from_slice(&COM_ID.to_be_bytes());
        pending[11] = 1;
        let mut sim = Sim {
            received: [
                pending,
                sync_reply(HOST as u8),
                lr0_reply(),
                frame(COM_ID, SESSION, &[0xfa]).to_vec(),
            ]
            .into(),
            ..Default::default()
        };

        let result = test_read(&mut sim).unwrap();
        assert_eq!(
            result,
            Lr0 {
                range_start: 0,
                range_length: 0x1_0000_0001,
                read_lock_enabled: true,
                write_lock_enabled: true,
                read_locked: true,
                write_locked: false,
            }
        );
        assert_eq!(sim.sent.len(), 3);
        assert!(sim.received.is_empty());
        let as_hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            as_hex(packet_payload(&sim.sent[0], COM_ID, Session::default()).unwrap()),
            concat!(
                "f8a800000000000000ffa8000000000000ff02f08400000069",
                "a8000002050000000200f200d020",
                "1bc5e27dbd51bb10c5012ae2f002ce69a610ff4bd6eb0e5a80b9f02da879e78b",
                "f3f203a80000000900010001f3f1f9f0000000f1"
            )
        );
        assert_eq!(
            as_hex(packet_payload(&sim.sent[1], COM_ID, SESSION).unwrap()),
            "f8a80000080200000001a80000000600000016f0f0f20303f3f20408f3f1f1f9f0000000f1"
        );
        assert_eq!(
            packet_payload(&sim.sent[2], COM_ID, SESSION).unwrap(),
            &[0xfa]
        );
    }

    #[test]
    fn rw_compatibility_changes_only_the_session_write_flag() {
        let read_only = start_session(COM_ID, HOST, false, &[0; 32]);
        let read_write = start_session(COM_ID, HOST, true, &[0; 32]);
        let changes: Vec<_> = read_only
            .iter()
            .zip(read_write.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .collect();
        // CALL, two UIDs, list, encoded host ID, then the Locking SP UID.
        assert_eq!(changes, vec![(HEADER + 34, (&0, &1))]);
    }

    #[test]
    fn authentication_rejection_is_terminal() {
        for (status, error) in [
            (1, "NOT_AUTHORIZED"),
            (0x0c, "INVALID_PARAMETER"),
            (0x12, "AUTHORITY_LOCKED_OUT"),
        ] {
            let reply = frame(
                COM_ID,
                Session::default(),
                &[0xf0, 0xf1, 0xf9, 0xf0, status, 0, 0, 0xf1],
            );
            let mut sim = Sim {
                received: [reply.to_vec()].into(),
                ..Default::default()
            };
            assert!(test_read(&mut sim).unwrap_err().to_string().contains(error));
            assert_eq!(sim.sent.len(), 1);
        }
    }

    #[test]
    fn refuses_other_sessions_and_incomplete_transport() {
        for responses in [
            vec![],
            vec![sync_reply(106)],
            vec![sync_reply(105), vec![0; 20]],
        ] {
            let sends = if responses.len() == 2 { 2 } else { 1 };
            let mut sim = Sim {
                received: responses.into(),
                ..Default::default()
            };
            assert!(test_read(&mut sim).is_err());
            assert_eq!(sim.sent.len(), sends);
        }
        let reply = lr0_reply();
        assert!(packet_payload(&reply, COM_ID, Session::default()).is_err());
        assert!(packet_payload(&reply, 0x1005, SESSION).is_err());
    }

    #[test]
    fn malformed_get_reply_is_rejected_and_matching_session_is_closed() {
        let reply = frame(
            COM_ID,
            SESSION,
            &[0xf0, 0xf0, 0xf1, 0xf1, 0xf9, 0xf0, 0, 0, 0, 0xf1],
        );
        let mut sim = Sim {
            received: [
                sync_reply(105),
                reply.to_vec(),
                frame(COM_ID, SESSION, &[0xfa]).to_vec(),
            ]
            .into(),
            ..Default::default()
        };
        assert!(
            test_read(&mut sim)
                .unwrap_err()
                .to_string()
                .contains("missing or invalid LR0")
        );
        assert_eq!(sim.sent.len(), 3);
    }

    #[test]
    fn requires_a_valid_close_response() {
        let mut sim = Sim {
            received: [sync_reply(105), lr0_reply()].into(),
            ..Default::default()
        };
        assert!(
            test_read(&mut sim)
                .unwrap_err()
                .to_string()
                .contains("EndSession receive")
        );
        assert_eq!(sim.sent.len(), 3);
    }

    #[test]
    fn rejects_truncated_frames_and_tokens() {
        let reply = lr0_reply();
        let payload = packet_payload(&reply, COM_ID, SESSION).unwrap();
        let end = HEADER + payload.len().next_multiple_of(4);
        for prefix in 0..end {
            assert!(packet_payload(&reply[..prefix], COM_ID, SESSION).is_err());
        }
        for prefix in 0..payload.len() {
            assert!(parse_lr0(&payload[..prefix]).is_err());
        }
        let mut duplicate = payload.to_vec();
        duplicate[7] = 3;
        assert!(
            parse_lr0(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn rejects_invalid_passwords_before_any_io() {
        let mut sim = Sim::default();
        for invalid in [String::new(), "x".repeat(257), "a\0b".into()] {
            assert!(
                read_lr0(
                    &mut sim,
                    COM_ID,
                    HOST,
                    false,
                    Zeroizing::new(invalid),
                    &SALT
                )
                .is_err()
            );
            assert!(sim.sent.is_empty());
        }
    }
}
