//! Cryptographic primitives for Loreyawen frame encryption

pub mod mic;
pub mod stream;

// Re-export the basic `cipher`-crate as its traits are used in public APIs
pub use cipher;
// Re-export the `aes`-crate if the feature is enabled
#[cfg(feature = "aes")]
pub use aes;

use cipher::{generic_array::typenum::U16, BlockCipher, BlockEncrypt, KeyInit};

/// A marker trait for a raw AES-128 implementations
///
/// # ⚠️ HAZMAT ⚠️
/// **With this trait, it is possible to inject faulty or incompatible implementations. Faulty or incompatible
/// implementations may result in a total and utter loss of any security.**
pub trait Aes128
where
    Self: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit<KeySize = U16> + Clone,
{
    // No member functions
}
#[cfg(feature = "aes")]
impl Aes128 for aes::Aes128 {
    // Nothing to implement here
}
