#![doc = include_str!("../README.md")]
#![no_std]
// Clippy lints
#![warn(clippy::large_stack_arrays)]
#![warn(clippy::arithmetic_side_effects)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::indexing_slicing)]
#![warn(clippy::panic)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
#![warn(clippy::unreachable)]
#![warn(clippy::missing_panics_doc)]
#![warn(clippy::allow_attributes_without_reason)]
#![warn(clippy::cognitive_complexity)]

pub mod crypto;
pub mod frame;

/// A message direction
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Direction {
    /// An uplink message from the end-device to the server
    Uplink = 0,
    /// A downlink message from the server to the end-device
    Downlink = 1,
}

/// A loreyawen session state
pub trait SessionState {
    /// The network session key used to authenticate packets
    fn nwkskey(&self) -> [u8; 16];
    /// The application session key used to encrypt payloads
    fn appskey(&self) -> [u8; 16];
    /// The device address
    fn device_address(&self) -> u32;

    /// The frame counter for packets with the given direction
    fn frame_counter(&self, direction: Direction) -> u32;
    /// Sets the frame counter for packets with the given direction
    fn set_frame_counter(&mut self, counter: u32, direction: Direction);
}

/// A builder to validate and decrypt a sealed frame into a plaintext
#[cfg(feature = "aes")]
pub type PlaintextBuilder<Session> = crate::frame::plaintext::PlaintextBuilder<Session, aes::Aes128>;

/// A builder to encrypt and seal a plaintext into a sealed frame
#[cfg(feature = "aes")]
pub type FrameBuilder<Session> = crate::frame::sealed::FrameBuilder<Session, aes::Aes128>;
