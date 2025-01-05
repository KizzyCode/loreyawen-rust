//! A loreyawen-specific wrapper around AES-CTR

use crate::crypto::cipher::generic_array::GenericArray;
use crate::crypto::cipher::{KeyIvInit, StreamCipher};
use crate::crypto::Aes128;
use crate::Direction;
use core::marker::PhantomData;
use ctr::Ctr128BE;

/// A loreyawen-specific wrapper around AES-CTR to compute and apply a cipherstream
#[derive(Debug, Clone, Copy)]
pub struct AesCtrBuilder<Aes = (), Key = (), Direction = (), Address = (), Counter = ()> {
    /// The underlying implementation
    aes: Aes,
    /// The key used for AES encryption
    appskey: Key,
    /// The direction of the message to compute/validate the MIC for
    direction: Direction,
    /// The address of the associated end-device
    address: Address,
    /// The frame counter of the message to compute the MIC for
    frame_counter: Counter,
}
impl AesCtrBuilder {
    /// Create a new cipherstream with the given key and AES implementation
    pub const fn new<Aes>(appskey: &[u8; 16]) -> AesCtrBuilder<PhantomData<Aes>, [u8; 16]> {
        AesCtrBuilder { aes: PhantomData, appskey: *appskey, direction: (), address: (), frame_counter: () }
    }
}
impl<Aes> AesCtrBuilder<PhantomData<Aes>, [u8; 16]> {
    /// Set the frame direction (Uplink or Downlink)
    pub fn set_direction(self, direction: Direction) -> AesCtrBuilder<PhantomData<Aes>, [u8; 16], Direction> {
        let Self { aes, appskey, address, frame_counter, .. } = self;
        AesCtrBuilder { aes, appskey, direction, address, frame_counter }
    }
}
impl<Aes> AesCtrBuilder<PhantomData<Aes>, [u8; 16], Direction> {
    /// Sets the address of the associated end-device
    pub fn set_address(self, address: u32) -> AesCtrBuilder<PhantomData<Aes>, [u8; 16], Direction, u32> {
        let Self { aes, appskey, direction, frame_counter, .. } = self;
        AesCtrBuilder { aes, appskey, direction, address, frame_counter }
    }
}
impl<Aes> AesCtrBuilder<PhantomData<Aes>, [u8; 16], Direction, u32> {
    /// Sets the address of the associated end-device
    pub fn set_frame_counter(self, counter: u32) -> AesCtrBuilder<PhantomData<Aes>, [u8; 16], Direction, u32, u32> {
        let Self { aes, appskey, direction, address, .. } = self;
        AesCtrBuilder { aes, appskey, direction, address, frame_counter: counter }
    }
}
impl<Aes> AesCtrBuilder<PhantomData<Aes>, [u8; 16], Direction, u32, u32> {
    /// Processes the given data by applying the keystream
    ///
    /// # Panics
    /// This function panics if data is longer than `255 * 16`.
    pub fn apply(self, data: &mut [u8])
    where
        Aes: Aes128,
    {
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
