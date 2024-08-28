//! Tests creating sealed frames
#![cfg(feature = "aes")]

mod session;

use loreyawen::{crypto::aes::Aes128, frame::sealed::FrameBuilder, Direction};
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

/// Seal uplink frames
#[test]
pub fn uplink() {
    // Seal frame
    let mut session = SESSION;
    let frame = FrameBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_payload(b"Testolope");

    // Verify frame and validate session
    assert_eq!(
        frame.deref(),
        b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9F\x8C\x33\xD3\x47\x9B\xAA\xB5\xB5"
    );
    assert_eq!(session.frame_counter_uplink, 1, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 0, "invalid downlink frame counter");

    // Do a follow-up frame computation to ensure that the updated state is used
    let frame = FrameBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_payload(b"Testolope");

    // Verify frame and validate session
    assert_eq!(
        frame.deref(),
        b"\xE0\xEF\xBE\xAD\xDE\x01\x00\x01\x58\xCA\xD6\xBC\xDE\x59\x37\x74\x78\xE5\x4B\x62\x64\x06\xF0\x9F\x6D"
    );
    assert_eq!(session.frame_counter_uplink, 2, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 0, "invalid downlink frame counter");
}

/// Seal downlink frames
#[test]
pub fn downlink() {
    // Seal frame
    let mut session = SESSION;
    let frame = FrameBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_payload(b"Testolope");

    // Verify frame and validate session
    assert_eq!(
        frame.deref(),
        b"\xE0\xEF\xBE\xAD\xDE\x00\x00\x01\xEC\x1C\x04\x6C\xC2\x83\x80\x7B\xDF\xB9\x9D\x6E\x15\x62\x62\x2D\x1A"
    );
    assert_eq!(session.frame_counter_uplink, 0, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 1, "invalid downlink frame counter");

    // Do a follow-up frame computation to ensure that the updated state is used
    let frame = FrameBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Downlink)
        .set_payload(b"Testolope");

    // Verify frame and validate session
    assert_eq!(
        frame.deref(),
        b"\xE0\xEF\xBE\xAD\xDE\x01\x00\x01\xD5\xE9\x9F\xB8\x45\xED\x61\x8B\x40\x50\xCE\xD8\x35\x5D\x85\x74\xD0"
    );
    assert_eq!(session.frame_counter_uplink, 0, "invalid uplink frame counter");
    assert_eq!(session.frame_counter_downlink, 2, "invalid downlink frame counter");
}

#[test]
#[should_panic]
pub fn exhausted_frame_counter() {
    // Setup session
    let mut session = SESSION;
    session.frame_counter_uplink = 0xFFFF_FFFF;

    // Seal frame
    let _frame = FrameBuilder::<_, Aes128>::new(&mut session)
        // Set uplink direction
        .set_direction(Direction::Uplink)
        .set_payload(b"Testolope");
}
