//! A builder to encrypt and seal a plaintext into a sealed frame

use crate::crypto::aesctr::AesCtrBuilder;
use crate::crypto::aescmac::AesCmacBuilder;
use crate::crypto::Aes128;
use crate::frame::builder::FrameBuilder;
use crate::frame::rawframe::RawFrame;
use crate::frame::MAX_MESSAGE_SIZE;
use crate::{Direction, SessionState};
use core::marker::PhantomData;
use core::ops::Deref;

/// A sealed frame
#[derive(Debug, Clone, Copy)]
pub struct SealedFrame {
    /// The sealed, raw frame
    raw: [u8; MAX_MESSAGE_SIZE],
    /// The length of the raw frame
    raw_len: usize,
}

// Implement encryption logic
impl<Aes, Session> FrameBuilder<PhantomData<Aes>, Session, Direction> {
    /// Sets and parses the frame
    ///
    /// # Panics
    /// This function panics if the payload is greater than [`MAX_PAYLOAD_SIZE`](crate::frame::MAX_PAYLOAD_SIZE).
    pub fn set_plaintext(self, plaintext: &[u8]) -> FrameBuilder<PhantomData<Aes>, Session, Direction, RawFrame> {
        let frame = RawFrame::new(plaintext);
        let Self { aes, session, direction, .. } = self;
        FrameBuilder { aes, session, direction, state: frame }
    }
}
impl<Aes, Session> FrameBuilder<PhantomData<Aes>, Session, Direction, RawFrame> {
    /// Sets the `FCtrl` byte
    pub fn set_frame_ctrl(mut self, frame_ctrl: u8) -> Self {
        self.state.set_frame_ctrl(frame_ctrl);
        self
    }

    /// Sets the `FPort` byte
    pub fn set_frame_port(mut self, frame_port: u8) -> Self {
        self.state.set_frame_port(frame_port);
        self
    }

    /// Encrypts the frame updates the session accordingly
    ///
    /// # Panics
    /// This function panics if the frame counter for the configured direction is exhausted.
    pub fn pack(mut self) -> FrameBuilder<PhantomData<Aes>, Session, Direction, SealedFrame>
    where
        Session: SessionState,
        Aes: Aes128,
    {
        // Get device address and next frame counter
        let address = self.session.device_address();
        let next_frame_counter = self.session.frame_counter(self.direction);

        // Assemble frame
        self.state.set_address(address);
        self.state.set_frame_counter_lsbs(next_frame_counter as u16);

        // Encrypt payload
        let appskey = self.session.appskey();
        AesCtrBuilder::new::<Aes>(appskey)
            .set_direction(self.direction)
            .set_address(address)
            .set_frame_counter(next_frame_counter)
            .apply(self.state.payload_mut());

        // Compute MIC
        let nwkskey = self.session.nwkskey();
        *self.state.mic_mut() = AesCmacBuilder::new::<Aes>(nwkskey)
            .set_direction(self.direction)
            .set_address(address)
            .set_frame_counter(next_frame_counter)
            .compute(self.state.header(), self.state.payload());

        // Commit next frame counter
        let next_frame_counter = next_frame_counter.checked_add(1).expect("frame counter is exhaused");
        self.session.set_frame_counter(next_frame_counter, self.direction);

        // Build output
        let (raw, raw_len) = self.state.into_frame();
        let output = SealedFrame { raw, raw_len };

        // Init next step
        let Self { aes, session, direction, .. } = self;
        FrameBuilder { aes, session, direction, state: output }
    }
}
impl<Aes, Session> Deref for FrameBuilder<PhantomData<Aes>, Session, Direction, SealedFrame> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        #[allow(clippy::indexing_slicing, reason = "Length is trusted here")]
        &self.state.raw[..self.state.raw_len]
    }
}
