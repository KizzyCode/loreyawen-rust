#![doc = include_str!("../README.md")]
#![no_std]
// Linter warnings
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
// Linter allowances
#![allow(non_contiguous_range_endpoints, reason = "This lint is stupid")]

pub mod crypto;
pub mod frame;
pub mod session;

// Re-export session types
pub use crate::frame::rawframe::RawFrame;
pub use crate::session::{Direction, SessionRefMut, SessionState};

/// A frame builder
#[cfg(not(feature = "aes"))]
pub type FrameBuilder = crate::frame::builder::FrameBuilder<()>;
/// A frame builder using [`aes::Aes128`] as default implementation
#[cfg(feature = "aes")]
pub type FrameBuilder = crate::frame::builder::FrameBuilder<aes::Aes128>;
