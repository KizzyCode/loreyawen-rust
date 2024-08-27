//! A builder to validate and decrypt a sealed frame into a plaintext

use crate::{
    crypto::{mic::MicBuilder, stream::CipherstreamBuilder, Aes128},
    frame::{raw::RawFrame, MAX_PAYLOAD_SIZE},
    Direction, SessionState,
};
use core::{marker::PhantomData, ops::Deref};

/// A builder to validate and decrypt a sealed frame into a plaintext
#[derive(Debug)]
pub struct PlaintextBuilder<Session, Aes> {
    /// The underlying session state
    session: Session,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Session, Aes> PlaintextBuilder<Session, Aes> {
    /// Create a new builder for the given session and implementation
    pub fn new(session: Session) -> Self {
        Self { session, _aes: PhantomData }
    }

    /// Set the direction of the associated message
    pub fn set_direction(self, direction: Direction) -> PlaintextBuilderWithDirection<Session, Aes> {
        PlaintextBuilderWithDirection { session: self.session, direction, _aes: self._aes }
    }
}

/// A builder to validate and decrypt a sealed frame into a plaintext
#[derive(Debug)]
pub struct PlaintextBuilderWithDirection<Session, Aes> {
    /// The underlying session state
    session: Session,
    /// The direction of the associated message
    direction: Direction,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Session, Aes> PlaintextBuilderWithDirection<Session, Aes> {
    /// Sets and parses the frame
    pub fn set_frame(self, frame: &[u8]) -> Option<PlaintextBuilderWithFrame<Session, Aes>> {
        let raw = RawFrame::parse(frame)?;
        Some(PlaintextBuilderWithFrame { session: self.session, direction: self.direction, raw, _aes: self._aes })
    }
}

/// A builder to validate and decrypt a sealed frame into a plaintext
#[derive(Debug)]
pub struct PlaintextBuilderWithFrame<Session, Aes> {
    /// The underlying session state
    session: Session,
    /// The direction of the associated message
    direction: Direction,
    /// The raw frame
    raw: RawFrame,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Session, Aes> PlaintextBuilderWithFrame<Session, Aes>
where
    Session: SessionState,
    Aes: Aes128,
{
    /// This is a reserved frame counter that must not be used by frames, so implementations can use it as marker value to
    /// e.g. mark a session as exhausted
    ///
    /// # Implementation Note
    /// The value of `u32::MAX` is chosen ofer e.g. `0`, because this way, an implementation can simply continue to
    /// increment the counter, so after the last allowed message (`MAX - 1`), it is normally incremented again, yielding
    /// `MAX`. However, since `MAX` is reserved and always rejected, the session cannot process any more messages, as there
    /// are no more valid frame counter values left.
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
    #[allow(non_contiguous_range_endpoints)]
    #[allow(clippy::missing_panics_doc)]
    pub fn unpack(mut self) -> Option<Plaintext> {
        // Validate address
        let device_address = self.session.device_address();
        let true = self.raw.address() == device_address else {
            // Apparently the message is not for us
            return None;
        };

        // Recover and validate frame counter
        let maybe_frame_counter = {
            // Recover the most-likely frame counter relative to the session state
            let next_frame_counter = self.session.frame_counter(self.direction);
            let frame_counter_lsbs = self.raw.frame_counter_lsbs();
            Self::recover_frame_counter(frame_counter_lsbs, next_frame_counter)
        };
        let frame_counter @ ..Self::RESERVED_FRAME_COUNTER = maybe_frame_counter else {
            // Reject `u32::MAX` as this means the session is exhausted
            return None;
        };

        // Validate MIC
        let nwkskey = self.session.nwkskey();
        let mic_valid = MicBuilder::<Aes>::new(&nwkskey)
            .set_direction(self.direction)
            .set_address(self.raw.address())
            .set_frame_counter(frame_counter)
            .verify(self.raw.header(), self.raw.payload(), self.raw.mic());
        let true = mic_valid else {
            // Reject invalid MICs
            return None;
        };

        // Decrypt payload
        let appskey = self.session.appskey();
        CipherstreamBuilder::<Aes>::new(&appskey)
            .set_direction(self.direction)
            .set_address(self.raw.address())
            .set_frame_counter(frame_counter)
            .apply(self.raw.payload_mut());

        // Commit next frame counter
        let next_frame_counter = frame_counter.saturating_add(1);
        self.session.set_frame_counter(next_frame_counter, self.direction);

        // Init next step
        let (plaintext, plaintext_len) = self.raw.into_payload();
        Some(Plaintext { plaintext, plaintext_len })
    }

    /// Recovers the full frame counter relative to the expected next frame counter
    ///
    /// # Security Considerations
    /// The best-effort recovery logic compares the lossy implicit frame counter to the expected next counter to recover
    /// the most-likely frame counter. If the resulting frame counter is not the correct one, MIC validation will fail.
    /// Therefore, an attacker might trick the logic into recovering a wrong frame counter, but they do not gain much
    /// there, as the message will be discarded.
    ///
    /// As a side-effect, this logic also protects against replay attacks, because the recovered frame counter is always
    /// equal to or higher than the next valid frame counter. If an attacker injects an older frame, this logic will
    /// erroneously recover a larger and thus non-matching frame counter, yielding a MIC validation error.
    ///
    /// # Important
    /// This logic may return the [`RESERVED_FRAME_COUNTER`], the caller must check for this.
    #[inline]
    fn recover_frame_counter(frame_counter_lsbs: u16, next_frame_counter: u32) -> u32 {
        // Recover the frame counter
        match (next_frame_counter & 0xFFFF_0000) | (frame_counter_lsbs as u32) {
            recovered if recovered >= next_frame_counter => recovered,
            recovered => recovered.saturating_add(0x1_0000),
        }
    }
}

/// The decrypted frame payload
#[derive(Debug, Clone, Copy)]
pub struct Plaintext {
    /// The decrypted plaintext buffer
    plaintext: [u8; MAX_PAYLOAD_SIZE],
    /// The amount of bytes within the payload buffer
    plaintext_len: usize,
}
impl Deref for Plaintext {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // Note: The plaintext length is assumed to be valid
        #[allow(clippy::indexing_slicing)]
        &self.plaintext[..self.plaintext_len]
    }
}
