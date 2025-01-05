//! A loreyawen "proprietary" frame

pub mod builder;
pub mod builderopen;
pub mod builderseal;
pub mod raw;

use crate::frame::raw::RawFrame;

/// The maximum message size
pub const MAX_MESSAGE_SIZE: usize = 255;
/// The maximum size of a payload
pub const MAX_PAYLOAD_SIZE: usize = MAX_MESSAGE_SIZE - RawFrame::HEADER_SIZE - RawFrame::MIC_SIZE;
