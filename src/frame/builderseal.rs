//! A builder to encrypt and seal a plaintext into a sealed frame

use crate::crypto::aescmac::AesCmacBuilder;
use crate::crypto::aesctr::AesCtrBuilder;
use crate::crypto::Aes128;
use crate::frame::builder::FrameBuilder;
use crate::frame::rawframe::RawFrame;
use crate::frame::MAX_MESSAGE_SIZE;
use crate::{Direction, SessionState};
use core::array::IntoIter;
use core::iter::Take;
use core::ops::Deref;

/// A plaintext intermediate frame
#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct IntermediateFrame {
    /// The underlying raw frame
    raw: RawFrame,
}

/// A sealed frame
#[derive(Debug, Clone, Copy)]
pub struct SealedFrame {
    /// The sealed, raw frame
    raw: [u8; MAX_MESSAGE_SIZE],
    /// The length of the raw frame
    raw_len: usize,
}
impl SealedFrame {
    /// An all-zero sealed frame for e.g. array initialization
    pub const ZERO: Self = Self { raw: [0; MAX_MESSAGE_SIZE], raw_len: 0 };
}
impl Deref for SealedFrame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        #[allow(clippy::indexing_slicing, reason = "Length is trusted here")]
        &self.raw[..self.raw_len]
    }
}
impl IntoIterator for SealedFrame {
    type Item = u8;
    type IntoIter = Take<IntoIter<u8, MAX_MESSAGE_SIZE>>;

    fn into_iter(self) -> Self::IntoIter {
        self.raw.into_iter().take(self.raw_len)
    }
}

// Implement encryption logic
impl<Aes, Session> FrameBuilder<Aes, Session, Direction> {
    /// Sets and parses the frame
    ///
    /// # Panics
    /// This function panics if the payload is greater than [`MAX_PAYLOAD_SIZE`](crate::frame::MAX_PAYLOAD_SIZE).
    pub fn set_plaintext(self, plaintext: &[u8]) -> FrameBuilder<Aes, Session, Direction, IntermediateFrame> {
        // Create frame
        let raw = RawFrame::new(plaintext);
        let frame = IntermediateFrame { raw };

        // Init next step
        let Self { aes, session, direction, .. } = self;
        FrameBuilder { aes, session, direction, state: frame }
    }
}
impl<Aes, Session> FrameBuilder<Aes, Session, Direction, IntermediateFrame> {
    /// Sets the `FCtrl` byte
    pub fn set_frame_ctrl(mut self, frame_ctrl: u8) -> Self {
        self.state.raw.set_frame_ctrl(frame_ctrl);
        self
    }

    /// Sets the `FPort` byte
    pub fn set_frame_port(mut self, frame_port: u8) -> Self {
        self.state.raw.set_frame_port(frame_port);
        self
    }

    /// Encrypts the frame updates the session accordingly
    ///
    /// # Panics
    /// This function panics if the frame counter for the configured direction is exhausted.
    pub fn pack(mut self) -> FrameBuilder<Aes, Session, Direction, SealedFrame>
    where
        Session: SessionState,
        Aes: Aes128,
    {
        // Get device address and next frame counter
        let address = self.session.device_address();
        let next_frame_counter = self.session.frame_counter(self.direction);

        // Assemble frame
        self.state.raw.set_address(address);
        self.state.raw.set_frame_counter_lsbs(next_frame_counter as u16);

        // Encrypt payload
        let appskey = self.session.appskey();
        AesCtrBuilder::new::<Aes>(appskey)
            .set_direction(self.direction)
            .set_address(address)
            .set_frame_counter(next_frame_counter)
            .apply(self.state.raw.payload_mut());

        // Compute MIC
        let nwkskey = self.session.nwkskey();
        *self.state.raw.mic_mut() = AesCmacBuilder::new::<Aes>(nwkskey)
            .set_direction(self.direction)
            .set_address(address)
            .set_frame_counter(next_frame_counter)
            .compute(self.state.raw.header(), self.state.raw.payload());

        // Commit next frame counter
        let next_frame_counter = next_frame_counter.checked_add(1).expect("frame counter is exhaused");
        self.session.set_frame_counter(next_frame_counter, self.direction);

        // Build output
        let (raw, raw_len) = self.state.raw.into_frame();
        let output = SealedFrame { raw, raw_len };

        // Init next step
        let Self { aes, session, direction, .. } = self;
        FrameBuilder { aes, session, direction, state: output }
    }
}
impl<Aes, Session> Deref for FrameBuilder<Aes, Session, Direction, SealedFrame> {
    type Target = SealedFrame;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}
