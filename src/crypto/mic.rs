//! A loreyawen-specific wrapper around AES-CMAC

use crate::{
    crypto::{cipher::generic_array::GenericArray, Aes128},
    Direction,
};
use cmac::{Cmac, Mac};
use core::{fmt::Debug, marker::PhantomData};

/// A loreyawen-specific wrapper around AES-CMAC to compute/validate a MIC for a message
#[derive(Debug)]
pub struct MicBuilder<Aes> {
    /// The key used for CMAC computation
    nwkskey: [u8; 16],
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> MicBuilder<Aes> {
    /// Create a new MIC builder with the given key
    pub const fn new(nwkskey: &[u8; 16]) -> Self {
        Self { nwkskey: *nwkskey, _aes: PhantomData }
    }

    /// Sets the direction of the message to compute/validate the MIC for
    pub fn set_direction(&self, direction: Direction) -> MicBuilderWithDirection<Aes> {
        MicBuilderWithDirection { nwkskey: self.nwkskey, direction, _aes: self._aes }
    }
}

/// A loreyawen-specific wrapper around AES-CMAC to compute or validate a MIC for a message
#[derive(Debug)]
pub struct MicBuilderWithDirection<Aes> {
    /// The key used for CMAC computation
    nwkskey: [u8; 16],
    /// The direction of the message to compute/validate the MIC for
    direction: Direction,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> MicBuilderWithDirection<Aes> {
    /// Sets the address of the associated end-device
    pub fn set_address(&self, address: u32) -> MicBuilderWithAddress<Aes> {
        MicBuilderWithAddress { nwkskey: self.nwkskey, direction: self.direction, address, _aes: self._aes }
    }
}

/// A loreyawen-specific wrapper around AES-CMAC to compute or validate a MIC for a message
#[derive(Debug)]
pub struct MicBuilderWithAddress<Aes> {
    /// The key used for CMAC computation
    nwkskey: [u8; 16],
    /// The direction of the message to compute/validate the MIC for
    direction: Direction,
    /// The address of the associated end-device
    address: u32,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> MicBuilderWithAddress<Aes> {
    /// Set the frame counter of the message to compute/validate the MIC for
    pub fn set_frame_counter(&self, frame_counter: u32) -> MicBuilderWithFrameCounter<Aes> {
        MicBuilderWithFrameCounter {
            nwkskey: self.nwkskey,
            direction: self.direction,
            address: self.address,
            frame_counter,
            _aes: self._aes,
        }
    }
}

/// A loreyawen-specific wrapper around AES-CMAC to compute or validate a MIC for a message
#[derive(Debug)]
pub struct MicBuilderWithFrameCounter<Aes> {
    /// The key used for CMAC computation
    nwkskey: [u8; 16],
    /// The direction of the message to compute the MIC for
    direction: Direction,
    /// The address of the associated end-device
    address: u32,
    /// The frame counter of the message to compute the MIC for
    frame_counter: u32,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> MicBuilderWithFrameCounter<Aes>
where
    Aes: Aes128,
{
    /// Compute the MIC for a given message
    ///
    /// # Panics
    /// This function panics if the total message length is longer than `255` bytes.
    pub fn compute(self, header: &[u8], payload: &[u8]) -> [u8; 8] {
        // Compute and return MIC
        let mac = self.cmac(header, payload).finalize().into_bytes();
        *mac.first_chunk().expect("MAC is too short")
    }

    /// Validates the MIC for a given message
    #[must_use]
    pub fn verify(self, header: &[u8], payload: &[u8], expected_mic: &[u8; 8]) -> bool {
        // Ensure the message length is within our constraints
        let total_length = header.len().saturating_add(payload.len());
        let ..=255 = total_length else {
            // Reject the message as it is too long
            return false;
        };

        // Compute and validate MIC
        self.cmac(header, payload).verify_truncated_left(expected_mic).is_ok()
    }

    /// Initializes a CMAC state with the given message but does not finalize it
    fn cmac(&self, header: &[u8], payload: &[u8]) -> Cmac<Aes> {
        // Compute total length
        let message_len = header.len().saturating_add(payload.len());
        let message_len = u8::try_from(message_len).expect("Message is too large");

        // Build block 0 and prepare key
        let block0 = self.block0(self.direction, self.address, self.frame_counter, message_len);
        let key = GenericArray::from_slice(&self.nwkskey);

        // Compute CMAC
        let mut cmac: Cmac<Aes> = Cmac::new(key);
        cmac.update(&block0);
        cmac.update(header);
        cmac.update(payload);
        cmac
    }

    /// Generates the implicit block0, which is used to tie the message to its context
    #[inline]
    fn block0(&self, direction: Direction, address: u32, frame_counter: u32, message_len: u8) -> [u8; 16] {
        // Destructure address and counter into bytes
        let address = address.to_le_bytes();
        let counter = frame_counter.to_le_bytes();

        // Build block0
        #[rustfmt::skip]
        return [
            // Static preamble
            0x49, 0x00, 0x00, 0x00, 0x00,
            // The message direction
            direction as u8,
            // The end-device address
            address[0], address[1], address[2], address[3],
            // The frame counter
            counter[0], counter[1], counter[2], counter[3],
            // Another static byte
            0x00,
            // The message length
            message_len
        ];
    }
}
