//! A builder to validate and decrypt a sealed frame into a plaintext

use crate::Direction;
use core::marker::PhantomData;

/// A frame builder
#[derive(Debug, Clone, Copy)]
pub struct FrameBuilder<Aes = (), Session = (), Direction = (), State = ()> {
    /// The underlying AES implementation
    pub(in crate::frame) aes: Aes,
    /// The underlying session state
    pub(in crate::frame) session: Session,
    /// The frame direction (Uplink or Downlink)
    pub(in crate::frame) direction: Direction,
    /// The transformation state
    pub(in crate::frame) state: State,
}
impl FrameBuilder {
    /// Create a new plaintext with the given session and AES implementation
    #[cfg(not(feature = "aes"))]
    pub const fn new<Aes, Session>(session: Session) -> FrameBuilder<PhantomData<Aes>, Session> {
        FrameBuilder { aes: PhantomData, session, direction: (), state: () }
    }
    /// Create a new plaintext with the given session
    #[cfg(feature = "aes")]
    pub const fn new<Session>(session: Session) -> FrameBuilder<PhantomData<aes::Aes128>, Session> {
        FrameBuilder { aes: PhantomData, session, direction: (), state: () }
    }
}
impl<Aes, Session> FrameBuilder<PhantomData<Aes>, Session> {
    /// Set the frame direction (Uplink or Downlink)
    pub fn set_direction(self, direction: Direction) -> FrameBuilder<PhantomData<Aes>, Session, Direction> {
        let Self { aes, session, state, .. } = self;
        FrameBuilder { aes, session, direction, state }
    }
}
