//! A loreyawen "proprietary" frame

pub mod plaintext;
mod raw;
pub mod sealed;

/// The maximum message size
pub const MAX_MESSAGE_SIZE: usize = 256;
/// The maximum size of a payload
pub const MAX_PAYLOAD_SIZE: usize = MAX_MESSAGE_SIZE - 16;
