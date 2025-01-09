//! A builder to validate and decrypt a sealed frame into a plaintext

use crate::Direction;
use core::marker::PhantomData;

/// An unspecified AES implementation
pub type AesUnspecified = ();

/// The selected default AES implementation (unspecified)
#[cfg(not(feature = "aes"))]
pub type DefaultAes = ();

/// The selected default AES implementation ([`aes::Aes128`])
#[cfg(feature = "aes")]
pub type DefaultAes = aes::Aes128;

/// A frame builder
#[derive(Debug, Clone, Copy)]
pub struct FrameBuilder<Aes, Session = (), Direction = (), State = ()> {
    /// A type reference to the underlying AES implementation
    pub(in crate::frame) aes: PhantomData<Aes>,
    /// The underlying session state
    pub(in crate::frame) session: Session,
    /// The frame direction (Uplink or Downlink)
    pub(in crate::frame) direction: Direction,
    /// The transformation state
    pub(in crate::frame) state: State,
}
impl<Aes> FrameBuilder<Aes> {
    /// Create a new frame builder with the given session
    pub const fn new<Session>(session: Session) -> FrameBuilder<Aes, Session> {
        FrameBuilder { aes: PhantomData, session, direction: (), state: () }
    }
}
impl<Aes, Session> FrameBuilder<Aes, Session> {
    /// Set the frame direction (Uplink or Downlink)
    pub fn set_direction(self, direction: Direction) -> FrameBuilder<Aes, Session, Direction> {
        let Self { aes, session, state, .. } = self;
        FrameBuilder { aes, session, direction, state }
    }
}
