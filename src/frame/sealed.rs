//! A builder to encrypt and seal a plaintext into a sealed frame

use crate::{
    crypto::{mic::MicBuilder, stream::CipherstreamBuilder, Aes128},
    frame::{raw::RawFrame, MAX_MESSAGE_SIZE},
    Direction, SessionState,
};
use core::{marker::PhantomData, ops::Deref};

/// A builder to encrypt and seal a plaintext into a sealed frame
#[derive(Debug)]
pub struct FrameBuilder<Session, Aes> {
    /// The underlying session state
    session: Session,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Session, Aes> FrameBuilder<Session, Aes> {
    /// Create a new builder for the given session and implementation
    pub fn new(session: Session) -> Self {
        Self { session, _aes: PhantomData }
    }

    /// Set the direction of the associated message
    pub fn set_direction(self, direction: Direction) -> FrameBuilderWithDirection<Session, Aes> {
        FrameBuilderWithDirection { session: self.session, direction, _aes: self._aes }
    }
}

/// A builder to encrypt and seal a plaintext into a sealed frame
#[derive(Debug)]
pub struct FrameBuilderWithDirection<Session, Aes> {
    /// The underlying session state
    session: Session,
    /// The direction of the associated message
    direction: Direction,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Session, Aes> FrameBuilderWithDirection<Session, Aes>
where
    Session: SessionState,
    Aes: Aes128,
{
    /// Sets the payload and encrypts it abd updates the session accordingly
    ///
    /// # Panics
    /// This function panics if the payload is greater than [`MAX_PAYLOAD_SIZE`](crate::frame::MAX_PAYLOAD_SIZE). This function also panics if if the
    /// frame counter for the configured direction is exhaused.
    pub fn set_payload(mut self, payload: &[u8]) -> Frame {
        // Get device address and next frame counter
        let address = self.session.device_address();
        let next_frame_counter = self.session.frame_counter(self.direction);

        // Assemble frame
        let mut raw = RawFrame::new(payload);
        raw.set_address(address);
        raw.set_frame_counter_lsbs(next_frame_counter as u16);

        // Encrypt payload
        let appskey = self.session.appskey();
        CipherstreamBuilder::<Aes>::new(appskey)
            .set_direction(self.direction)
            .set_address(address)
            .set_frame_counter(next_frame_counter)
            .apply(raw.payload_mut());

        // Compute MIC
        let nwkskey = self.session.nwkskey();
        *raw.mic_mut() = MicBuilder::<Aes>::new(nwkskey)
            .set_direction(self.direction)
            .set_address(address)
            .set_frame_counter(next_frame_counter)
            .compute(raw.header(), raw.payload());

        // Commit next frame counter
        let next_frame_counter = next_frame_counter.checked_add(1).expect("frame counter is exhaused");
        self.session.set_frame_counter(next_frame_counter, self.direction);

        // Init next step
        let (frame, frame_len) = raw.into_frame();
        Frame { frame, frame_len }
    }
}

/// The encrypted, final frame
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    /// The frame data buffer
    frame: [u8; MAX_MESSAGE_SIZE],
    /// The amount of bytes within the frame data buffer
    frame_len: usize,
}
impl Deref for Frame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // Note: The frame length is assumed to be valid
        #[allow(clippy::indexing_slicing)]
        &self.frame[..self.frame_len]
    }
}
