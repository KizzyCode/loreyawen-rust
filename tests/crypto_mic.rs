//! Tests the cipher stream implementation
#![cfg(feature = "aes")]
#![cfg(feature = "extended-mic")]

mod session;

use loreyawen::crypto::aes::Aes128;
use loreyawen::crypto::aescmac::AesCmacBuilder;
use loreyawen::Direction;
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
    let mic = AesCmacBuilder::new::<Aes128>(&SESSION.appskey)
        .set_direction(Direction::Uplink)
        .set_address(SESSION.device_address)
        .set_frame_counter(SESSION.frame_counter_uplink)
        .compute(b"Test", b"olope");

    // Validate MIC
    assert_eq!(&mic, b"\xB1\xA3\x1A\xA9\xF5\xD3\x3B\xDC", "unexpected MIC");
}

/// Tests the encryption for downlink frames
#[test]
fn downlink() {
    // Test downlink
    let mic = AesCmacBuilder::new::<Aes128>(&SESSION.appskey)
        .set_direction(Direction::Downlink)
        .set_address(SESSION.device_address)
        .set_frame_counter(SESSION.frame_counter_uplink)
        .compute(b"Test", b"olope");

    // Validate MIC
    assert_eq!(&mic, b"\x47\xC2\x4B\x8C\x3B\x1D\x20\x26", "unexpected MIC");
}
