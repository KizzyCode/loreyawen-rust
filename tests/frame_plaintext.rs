//! Tests opening sealed frames
#![cfg(feature = "aes")]

mod session;

use loreyawen::{crypto::aes::Aes128, frame::plaintext::PlaintextBuilder, Direction};
use session::MockSession;
use std::ops::Deref;

/// The mock session to use in the tests
pub const SESSION: MockSession = MockSession {
    nwkskey: *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
    appskey: *b"\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00",
    device_address: 0xDEADBEEF,
    frame_counter_uplink: 0,
    frame_counter_downlink: 0,
};

/// Open uplink frames
#[test]
pub fn uplink() {
    // Open frame
    let mut session = SESSION;
    let plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9F\x8C\x33\xD3\x47\x9B\xAA\xB5\xB5")
        .expect("unexpected invalid frame")
        .unpack()
        .expect("unexpected failure when unpacking frame");

    // Verify frame and validate session
    assert_eq!(plaintext.deref(), b"Testolope");
    assert_eq!(session.frame_counter_uplink, 1, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 0, "invalid downlink frame counter");

    // Do a follow-up frame computation to ensure that the updated state is used
    let plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x01\x00\x01\x58\xCA\xD6\xBC\xDE\x59\x37\x74\x78\xE5\x4B\x62\x64\x06\xF0\x9F\x6D")
        .expect("unexpected invalid frame")
        .unpack()
        .expect("unexpected failure when unpacking frame");

    // Verify frame and validate session
    assert_eq!(plaintext.deref(), b"Testolope");
    assert_eq!(session.frame_counter_uplink, 2, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 0, "invalid downlink frame counter");

    // Uplink with overflow
    let plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        // Frame has been sealed with frame counter `0x0001_0000`
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xF2\x1A\x03\xEE\xF9\xF5\x2C\xF7\x8A\xCB\x59\x41\x58\x71\x99\x4A\x9C")
        .expect("unexpected invalid frame")
        .unpack()
        .expect("unexpected failure when unpacking frame");

    // Verify frame and validate session
    assert_eq!(plaintext.deref(), b"Testolope");
    assert_eq!(session.frame_counter_uplink, 0x0001_0001, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 0, "invalid downlink frame counter");
}

/// Open downlink frames
#[test]
pub fn downlink() {
    // Seal frame
    let mut session = SESSION;
    let plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xEC\x1C\x04\x6C\xC2\x83\x80\x7B\xDF\xB9\x9D\x6E\x15\x62\x62\x2D\x1A")
        .expect("unexpected invalid frame")
        .unpack()
        .expect("unexpected failure when unpacking frame");

    // Verify frame and validate session
    assert_eq!(plaintext.deref(), b"Testolope");
    assert_eq!(session.frame_counter_uplink, 0, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 1, "invalid downlink frame counter");

    // Do a follow-up frame computation to ensure that the updated state is used
    let plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x01\x00\x01\xD5\xE9\x9F\xB8\x45\xED\x61\x8B\x40\x50\xCE\xD8\x35\x5D\x85\x74\xD0")
        .expect("unexpected invalid frame")
        .unpack()
        .expect("unexpected failure when unpacking frame");

    // Verify frame and validate session
    assert_eq!(plaintext.deref(), b"Testolope");
    assert_eq!(session.frame_counter_uplink, 0, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 2, "invalid downlink frame counter");

    // Downlink with overflow
    let plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        // Frame has been sealed with frame counter `0x0001_0000`
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xE3\xB3\x43\x5D\x93\xB9\x3A\x8F\x88\xB2\x54\x8E\x9F\xDA\xF4\x74\x95")
        .expect("unexpected invalid frame")
        .unpack()
        .expect("unexpected failure when unpacking frame");

    // Verify frame and validate session
    assert_eq!(plaintext.deref(), b"Testolope");
    assert_eq!(session.frame_counter_uplink, 0, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 0x0001_0001, "invalid downlink frame counter");
}

/// Open an invalid frame (format)
#[test]
pub fn generic_invalid_format() {
    // Open invalid uplink frame
    let mut session = SESSION;
    let maybe_plaintext_builder = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xA0\xEF\xBE\xAD\xDE\x00\x00\x01\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9F\x8C\x33\xD3\x47\x9B\xAA\xB5\xB5");
    assert!(maybe_plaintext_builder.is_none(), "unexpected success when unpacking plaintext");
}

/// Open an invalid frame (tampered)
#[test]
pub fn uplink_downlink_tampered_data() {
    // Open invalid uplink frame
    let mut session = SESSION;
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9E\x8C\x33\xD3\x47\x9B\xAA\xB5\xB5")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");

    // Open invalid downlink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xEC\x1C\x04\x6C\xC2\x83\x80\x7B\xDE\xB9\x9D\x6E\x15\x62\x62\x2D\x1A")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");
}

/// Open an invalid frame (counter too old/invalid recovered counter)
#[test]
pub fn generic_outdated_counter() {
    // Modify session counters
    let mut session = SESSION;
    session.frame_counter_uplink = 1;
    session.frame_counter_downlink = 1;

    // Open invalid uplink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9F\x8C\x33\xD3\x47\x9B\xAA\xB5\xB5")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");

    // Open invalid downlink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xEC\x1C\x04\x6C\xC2\x83\x80\x7B\xDF\xB9\x9D\x6E\x15\x62\x62\x2D\x1A")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");
}

/// Open an invalid frame (counter yields u32::MAX)
#[test]
pub fn generic_invalid_counter() {
    // Modify session counters
    let mut session = SESSION;
    session.frame_counter_uplink = 0xFFFF_FFFF;
    session.frame_counter_downlink = 0xFFFF_FFFF;

    // Open invalid uplink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\xFF\xFF\x01\x95\xDD\x21\xA5\x48\x3A\xDE\x18\x40\x65\x6A\xCB\x14\xBB\xF4\xBF\x72")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");

    // Open invalid downlink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\xFF\xFF\x01\x17\xA8\xE1\x3C\xA6\xD9\xDB\x87\xA6\xF6\x1F\xF6\xF6\x0E\x06\xB9\xB1")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");
}

/// Open an invalid frame (invalid direction)
#[test]
pub fn uplink_downlink_invalid_direction() {
    // Open invalid uplink frame
    let mut session = SESSION;
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9F\x8C\x33\xD3\x47\x9B\xAA\xB5\xB5")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");

    // Open invalid downlink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xEC\x1C\x04\x6C\xC2\x83\x80\x7B\xDF\xB9\x9D\x6E\x15\x62\x62\x2D\x1A")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");
}

/// Open an invalid frame (invalid address)
#[test]
pub fn generic_invalid_address() {
    // Modify device name
    let mut session = SESSION;
    session.device_address = 0xCAFEBEEF;

    // Open invalid uplink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9F\x8C\x33\xD3\x47\x9B\xAA\xB5\xB5")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");

    // Open invalid downlink frame
    let maybe_plaintext = PlaintextBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_frame(b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xEC\x1C\x04\x6C\xC2\x83\x80\x7B\xDF\xB9\x9D\x6E\x15\x62\x62\x2D\x1A")
        .expect("unexpected invalid frame")
        .unpack();
    assert!(maybe_plaintext.is_none(), "unexpected success when unpacking plaintext");
}
