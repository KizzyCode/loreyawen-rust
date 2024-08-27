//! A loreyawen-specific wrapper around AES-CTR

use crate::{
    crypto::{
        cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
        Aes128,
    },
    Direction,
};
use core::marker::PhantomData;
use ctr::Ctr128BE;

/// A loreyawen-specific wrapper around AES-CTR to compute and apply a cipherstream
#[derive(Debug)]
pub struct CipherstreamBuilder<Aes> {
    /// The key used for cipherstream computation
    appskey: [u8; 16],
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> CipherstreamBuilder<Aes> {
    /// Create a new cipherstream builder with the given key
    pub const fn new(appskey: &[u8; 16]) -> Self {
        Self { appskey: *appskey, _aes: PhantomData }
    }

    /// Sets the direction of the message to compute the cipherstream for
    pub fn set_direction(&self, direction: Direction) -> CipherstreamBuilderWithDirection<Aes> {
        CipherstreamBuilderWithDirection { appskey: self.appskey, direction, _aes: self._aes }
    }
}

/// A loreyawen-specific wrapper around AES-CTR to compute and apply a cipherstream
#[derive(Debug)]
pub struct CipherstreamBuilderWithDirection<Aes> {
    /// The key used for cipherstream computation
    appskey: [u8; 16],
    /// The direction of the message to compute the cipherstream for
    direction: Direction,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> CipherstreamBuilderWithDirection<Aes> {
    /// Sets the address of the associated end-device
    pub fn set_address(&self, address: u32) -> CipherstreamBuilderWithAddress<Aes> {
        CipherstreamBuilderWithAddress { appskey: self.appskey, direction: self.direction, address, _aes: self._aes }
    }
}

/// A loreyawen-specific wrapper around AES-CTR to compute and apply a cipherstream
#[derive(Debug)]
pub struct CipherstreamBuilderWithAddress<Aes> {
    /// The key used for cipherstream computation
    appskey: [u8; 16],
    /// The direction of the message to compute the cipherstream for
    direction: Direction,
    /// The address of the associated end-device
    address: u32,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> CipherstreamBuilderWithAddress<Aes> {
    /// Set the frame counter of the message to compute the cipherstream for
    pub fn set_frame_counter(&self, frame_counter: u32) -> CipherstreamBuilderWithFrameCounter<Aes> {
        CipherstreamBuilderWithFrameCounter {
            appskey: self.appskey,
            direction: self.direction,
            address: self.address,
            frame_counter,
            _aes: self._aes,
        }
    }
}

/// A loreyawen-specific wrapper around AES-CTR to compute and apply a cipherstream
#[derive(Debug)]
pub struct CipherstreamBuilderWithFrameCounter<Aes> {
    /// The key used for cipherstream computation
    appskey: [u8; 16],
    /// The direction of the message to compute the cipherstream for
    direction: Direction,
    /// The address of the associated end-device
    address: u32,
    /// The frame counter of the message to compute the cipherstream for
    frame_counter: u32,
    /// The underlying implementation
    _aes: PhantomData<Aes>,
}
impl<Aes> CipherstreamBuilderWithFrameCounter<Aes>
where
    Aes: Aes128,
{
    /// Processes the given data by applying the keystream
    ///
    /// # Panics
    /// This function panics if data is longer than `255 * 16`.
    pub fn apply(self, data: &mut [u8]) {
        // Ensure we do not encrypt more than 256 blocks, since we must only use the last byte as counter; the other
        //  bytes are defined by LoRaWAN to pin the message context
        assert!(data.len() <= 255 * 16, "Data is too long");

        // Build counter block 0 and prepare key
        let block0 = self.block0(self.direction, self.address, self.frame_counter);
        let iv = GenericArray::from_slice(&block0);
        let key = GenericArray::from_slice(&self.appskey);

        // Initialize the cipher and process data
        let mut ctr: Ctr128BE<Aes> = Ctr128BE::new(key, iv);
        ctr.apply_keystream(data);
    }

    /// Generates the implicit block0, which is used to tie the message to its context
    #[inline]
    fn block0(&self, direction: Direction, address: u32, frame_counter: u32) -> [u8; 16] {
        // Destructure address and counter into bytes
        let address = address.to_le_bytes();
        let counter = frame_counter.to_le_bytes();

        // Build block0
        #[rustfmt::skip]
        return [
            // Static preamble
            0x01, 0x00, 0x00, 0x00, 0x00,
            // The message direction
            direction as u8,
            // The end-device address
            address[0], address[1], address[2], address[3],
            // The frame counter
            counter[0], counter[1], counter[2], counter[3],
            // Another static byte
            0x00,
            // The first block has an index of 1
            0x01
        ];
    }
}
