//! Tests the cipher stream implementation
#![cfg(feature = "aes")]

mod session;

use loreyawen::{
    crypto::{aes::Aes128, stream::CipherstreamBuilder},
    Direction,
};
use session::MockSession;

/// The mock session to use in the tests
pub const SESSION: MockSession = MockSession {
    nwkskey: *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
    appskey: *b"\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00",
    device_address: 0xDEADBEEF,
    frame_counter_uplink: 0,
    frame_counter_downlink: 0,
};

/// Tests the encryption for uplink frames
#[test]
fn uplink() {
    // Test uplink
    let mut data = *b"Testolope";
    CipherstreamBuilder::<Aes128>::new(&SESSION.appskey)
        .set_direction(Direction::Uplink)
        .set_address(SESSION.device_address)
        .set_frame_counter(SESSION.frame_counter_uplink)
        .apply(&mut data);

    // Validate ciphertext
    assert_eq!(&data, b"\x7B\xA4\xCB\xEB\x83\x76\x65\x05\x9F", "unexpected ciphertext");
}

/// Tests the encryption for downlink frames
#[test]
fn downlink() {
    // Test downlink
    let mut data = *b"Testolope";
    CipherstreamBuilder::<Aes128>::new(&SESSION.appskey)
        .set_direction(Direction::Downlink)
        .set_address(SESSION.device_address)
        .set_frame_counter(SESSION.frame_counter_uplink)
        .apply(&mut data);

    // Validate ciphertext
    assert_eq!(&data, b"\xEC\x1C\x04\x6C\xC2\x83\x80\x7B\xDF", "unexpected ciphertext")
}
