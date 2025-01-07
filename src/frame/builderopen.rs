//! `FrameBuilder` transisions to validate and decrypt a sealed frame into a plaintext

use crate::crypto::aescmac::AesCmacBuilder;
use crate::crypto::aesctr::AesCtrBuilder;
use crate::crypto::Aes128;
use crate::frame::builder::FrameBuilder;
use crate::frame::rawframe::RawFrame;
use crate::frame::MAX_PAYLOAD_SIZE;
use crate::{Direction, SessionState};
use core::ops::Deref;

/// A sealed intermediate frame
#[derive(Debug, Clone, Copy)]
pub struct SealedFrame {
    /// The underlying raw frame
    raw: RawFrame,
}

/// The decrypted frame
#[derive(Debug, Clone, Copy)]
pub struct PlaintextFrame {
    /// The frame counter
    frame_counter: u32,
    /// The `FCtrl` field
    frame_ctrl: u8,
    /// The `FPort` field
    frame_port: u8,
    /// The plaintext buffer
    plaintext: [u8; MAX_PAYLOAD_SIZE],
    /// The plaintext length
    plaintext_len: usize,
}

// Implement decryption logic
impl<Aes, Session> FrameBuilder<Aes, Session, Direction> {
    /// Parses a raw frame
    pub fn set_frame(self, frame: &[u8]) -> Option<FrameBuilder<Aes, Session, Direction, SealedFrame>> {
        // Parse frame
        let raw = RawFrame::parse(frame)?;
        let frame = SealedFrame { raw };

        // Init next step
        let Self { aes, session, direction, .. } = self;
        Some(FrameBuilder { aes, session, direction, state: frame })
    }
}
impl<Aes, Session> FrameBuilder<Aes, Session, Direction, SealedFrame> {
    /// This is a reserved frame counter that must not be used by frames, so implementations can use it as marker value
    /// to e.g. mark a session as exhausted
    ///
    /// # Implementation Note
    /// The value of `u32::MAX` is chosen over e.g. `0`, because this way, an implementation can simply continue to
    /// increment the counter. After the last allowed message (`MAX - 1`) has been received, another increment yields
    /// `MAX`, and since `MAX` is reserved and always rejected, the session automatically enters a state where it cannot
    /// process any more messages, as there are no more valid frame counter values left.
    pub(in crate::frame) const RESERVED_FRAME_COUNTER: u32 = u32::MAX;

    /// Validates the frame against the session and decrypts the plaintext
    ///
    /// # Implementation Details
    /// This step performs the following session-specific message validation and decryption steps in this order:
    /// 1. Validate the address to see if the message is really addressed to us
    /// 2. Attempt to recover the frame counter and make sure it does not exhaust the session
    /// 3. Validate the MIC over header and payload
    /// 4. Decrypt the payload
    /// 4. Commit the frame counter of the message to the message state
    pub fn unpack(mut self) -> Option<FrameBuilder<Aes, Session, Direction, PlaintextFrame>>
    where
        Session: SessionState,
        Aes: Aes128,
    {
        // Validate address
        let device_address = self.session.device_address();
        let true = self.state.raw.address() == device_address else {
            // Apparently the message is not for us
            return None;
        };

        // Recover and validate frame counter
        let maybe_frame_counter = {
            // Recover the most-likely frame counter relative to the session state
            let next_frame_counter = self.session.frame_counter(self.direction);
            let frame_counter_lsbs = self.state.raw.frame_counter_lsbs();
            Self::recover_frame_counter(frame_counter_lsbs, next_frame_counter)
        };
        let frame_counter @ ..Self::RESERVED_FRAME_COUNTER = maybe_frame_counter else {
            // Reject `u32::MAX` as this means the session is exhausted
            return None;
        };

        // Validate MIC
        let nwkskey = self.session.nwkskey();
        let mic_valid = AesCmacBuilder::new::<Aes>(nwkskey)
            .set_direction(self.direction)
            .set_address(self.state.raw.address())
            .set_frame_counter(frame_counter)
            .verify(self.state.raw.header(), self.state.raw.payload(), self.state.raw.mic());
        let true = mic_valid else {
            // Reject invalid MICs
            return None;
        };

        // Decrypt payload
        let appskey = self.session.appskey();
        AesCtrBuilder::new::<Aes>(appskey)
            .set_direction(self.direction)
            .set_address(self.state.raw.address())
            .set_frame_counter(frame_counter)
            .apply(self.state.raw.payload_mut());

        // Commit next frame counter
        let next_frame_counter = frame_counter.saturating_add(1);
        self.session.set_frame_counter(next_frame_counter, self.direction);

        // Build output struct
        let frame_ctrl = self.state.raw.frame_ctrl();
        let frame_port = self.state.raw.frame_port();
        let (plaintext, plaintext_len) = self.state.raw.into_payload();
        let output = PlaintextFrame { frame_counter, frame_ctrl, frame_port, plaintext, plaintext_len };

        // Init next step
        let Self { aes, session, direction, .. } = self;
        Some(FrameBuilder { aes, session, direction, state: output })
    }

    /// Recovers the full frame counter relative to the expected next frame counter
    ///
    /// # Security Considerations
    /// This best-effort recovery logic compares the lossy implicit frame counter to the expected next counter to
    /// recover the most-likely frame counter. If the resulting frame counter is not the correct one, MIC validation
    /// will fail. Therefore, an attacker might trick the logic into recovering a wrong frame counter, but they do not
    /// gain much there, as the message will be discarded.
    ///
    /// As a side-effect, this logic also protects against replay attacks, because the recovered frame counter is always
    /// equal to or higher than the next valid frame counter. If an attacker injects an older frame, this logic will
    /// erroneously recover a larger and thus non-matching frame counter, yielding a MIC validation error.
    ///
    /// # Important
    /// This function may return the [`RESERVED_FRAME_COUNTER`], the caller must check for this.
    #[inline]
    #[must_use]
    fn recover_frame_counter(frame_counter_lsbs: u16, next_frame_counter: u32) -> u32 {
        // Recover the frame counter
        match (next_frame_counter & 0xFFFF_0000) | (frame_counter_lsbs as u32) {
            recovered if recovered >= next_frame_counter => recovered,
            recovered => recovered.saturating_add(0x1_0000),
        }
    }
}
impl<Aes, Session> FrameBuilder<Aes, Session, Direction, PlaintextFrame> {
    /// Gets the frame counter
    pub fn frame_counter(&self) -> u32 {
        self.state.frame_counter
    }

    /// Gets the `FCtrl` byte
    pub fn frame_ctrl(&self) -> u8 {
        self.state.frame_ctrl
    }

    /// Gets the `FPort` byte
    pub fn frame_port(&self) -> u8 {
        self.state.frame_port
    }
}
impl<Aes, Session> Deref for FrameBuilder<Aes, Session, Direction, PlaintextFrame> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        #[allow(clippy::indexing_slicing, reason = "Length is trusted here")]
        &self.state.plaintext[..self.state.plaintext_len]
    }
}
