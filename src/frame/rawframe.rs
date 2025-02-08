//! A raw frame structure for (de-)serialisation

use crate::frame::{MAX_MESSAGE_SIZE, MAX_PAYLOAD_SIZE};

/// A raw frame structure for (de-)serialisation
///
/// # ⚠️ HAZMAT ⚠️
/// Raw frames are **unvalidated**. While they might be useful to quickly reject frames (e.g. due to format or address
/// mismatch), they __MUST NOT__ be used for any real purposes. Always treat the data from a [`RawFrame`] as untrusted
/// and potentially malicious.
///
/// # Implementation Note
/// `loreyawen` uses a LoRaWAN-proprietary frame format, with the following fields:
/// - 1 byte `MHDR`, fixed to `0b111_000_00` (indicates a "proprietary" frame for LoRaWAN version 1.0)
/// - 8 bytes `FHDR`, consisting of 4 bytes `DevAddr`, 1 byte `FCtrl`, 2 bytes `FCnt`, and 1 byte `FPort`
/// - N bytes encrypted payload
/// - 4 or 8 bytes `MIC` (which is just a less-truncated version of the default LoRaWAN MIC)
///
/// ```ascii
/// Loreyawen Frame:
/// MHDR[1] | DevAddr[4] | FCtrl[1] | FCnt[2] |     FOpts[0] |    FPort[1] | Payload[N] | MIC[4 or 8]
///
/// LoRaWAN Uplink/Downlink Frame as Reference:
/// MHDR[1] | DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] | FPort[0..1] | Payload[N] | MIC[4]
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RawFrame {
    /// The frame header
    header: [u8; Self::HEADER_SIZE],
    /// The payload buffer
    payload: [u8; MAX_PAYLOAD_SIZE],
    /// The amount of bytes within the payload buffer
    payload_len: usize,
    /// The MIC (Message Integrity Code)
    mic: [u8; Self::MIC_SIZE],
}
impl RawFrame {
    /// The message header byte for our proprietary LoRaWAN frames
    #[allow(clippy::unusual_byte_groupings, reason = "Uses the message header grouping")]
    const MHDR: u8 = 0b111_000_00;
    /// The header length in bytes
    pub const HEADER_SIZE: usize = 9;
    /// The MIC length in bytes
    pub const MIC_SIZE: usize = match cfg!(feature = "extended-mic") {
        true => 8,
        false => 4,
    };

    /// Create a new unitialized frame with only the fixed constants and the given payload set
    ///
    /// # Panics
    /// This function panics if the payload is larger than [`MAX_PAYLOAD_SIZE`]
    pub fn new(payload: &[u8]) -> Self {
        // Create an owned buffer...
        let mut payload_ = [0; MAX_PAYLOAD_SIZE];
        payload_.get_mut(..payload.len()).expect("payload is too large")
            // ... and copy the payload
            .copy_from_slice(payload);

        // Return the new frame
        RawFrame {
            header: [Self::MHDR, 0, 0, 0, 0, 0, 0, 0, 0],
            payload: payload_,
            payload_len: payload.len(),
            mic: [0; Self::MIC_SIZE],
        }
    }
    /// Parses the frame
    pub fn parse(frame: &[u8]) -> Option<Self> {
        // Split frame
        let payload_len = frame.len().checked_sub(Self::HEADER_SIZE)?.checked_sub(Self::MIC_SIZE)?;
        let (header, data) = frame.split_at_checked(Self::HEADER_SIZE)?;
        let (payload, mic) = data.split_at_checked(payload_len)?;

        // Get header and MIC as arrays and check header
        let header = header.first_chunk()?;
        let mic = mic.first_chunk()?;
        let _valid_header @ [Self::MHDR, _, _, _, _, _, _, _, _] = header else {
            // The header is unexpected
            return None;
        };

        // Copy the payload
        let mut payload_ = [0; MAX_PAYLOAD_SIZE];
        payload_.get_mut(..payload_len)?.copy_from_slice(payload);

        // Return the parsed frame
        Some(Self { header: *header, payload: payload_, payload_len, mic: *mic })
    }
    /// Serializes the frame and returns a tuple with the buffer and the amount of bytes in there (aka serialized frame
    /// length)
    pub fn into_frame(self) -> ([u8; MAX_MESSAGE_SIZE], usize) {
        // Serialize frame
        let mut buffer = [0; MAX_MESSAGE_SIZE];

        // Serialize the frame
        // Note: The buffer should always be able to hold the entire frame
        #[allow(clippy::indexing_slicing, reason = "Lengths should always be valid")]
        {
            // Write header, payload and MIC to the buffer
            buffer[..Self::HEADER_SIZE].copy_from_slice(&self.header);
            buffer[Self::HEADER_SIZE..][..self.payload_len].copy_from_slice(&self.payload[..self.payload_len]);
            buffer[Self::HEADER_SIZE..][self.payload_len..][..Self::MIC_SIZE].copy_from_slice(&self.mic);
        }

        // Return tuple
        // Note; This should always be smaller than `usize::MAX`
        #[allow(clippy::arithmetic_side_effects, reason = "This should never overflow")]
        let frame_length = Self::HEADER_SIZE + self.payload_len + Self::MIC_SIZE;
        (buffer, frame_length)
    }

    /// The header of the frame
    pub fn header(&self) -> &[u8; Self::HEADER_SIZE] {
        &self.header
    }

    /// The address of the end device associated with the frame
    pub fn address(&self) -> u32 {
        let [_, addr0, addr1, addr2, addr3, _, _, _, _] = self.header;
        u32::from_le_bytes([addr0, addr1, addr2, addr3])
    }
    /// The address of the end device associated with the frame
    pub fn set_address(&mut self, address: u32) {
        let [mhdr, _, _, _, _, fctrl, fcnt0, fcnt1, fport] = self.header;
        let [addr0, addr1, addr2, addr3] = address.to_le_bytes();
        self.header = [mhdr, addr0, addr1, addr2, addr3, fctrl, fcnt0, fcnt1, fport];
    }

    /// The least significant bytes of the frame counter
    pub fn frame_counter_lsbs(&self) -> u16 {
        let [_, _, _, _, _, _, fcnt0, fcnt1, _] = self.header;
        u16::from_le_bytes([fcnt0, fcnt1])
    }
    /// Sets the least significant bytes of the frame counter
    pub fn set_frame_counter_lsbs(&mut self, frame_counter_lsbs: u16) {
        let [mhdr, addr0, addr1, addr2, addr3, fctrl, _, _, fport] = self.header;
        let [fcnt0, fcnt1] = frame_counter_lsbs.to_le_bytes();
        self.header = [mhdr, addr0, addr1, addr2, addr3, fctrl, fcnt0, fcnt1, fport];
    }

    /// Gets the `FCtrl` byte
    pub fn frame_ctrl(&self) -> u8 {
        let [_, _, _, _, _, fctrl, _, _, _] = self.header;
        fctrl
    }
    /// Sets the `FCtrl` byte
    pub fn set_frame_ctrl(&mut self, frame_ctrl: u8) {
        let [mhdr, addr0, addr1, addr2, addr3, _, fcnt0, fcnt1, fport] = self.header;
        self.header = [mhdr, addr0, addr1, addr2, addr3, frame_ctrl, fcnt0, fcnt1, fport];
    }

    /// Gets the `FPort` byte
    pub fn frame_port(&self) -> u8 {
        let [_, _, _, _, _, _, _, _, fport] = self.header;
        fport
    }
    /// Sets the `FCtrl` byte
    pub fn set_frame_port(&mut self, frame_port: u8) {
        let [mhdr, addr0, addr1, addr2, addr3, fctrl, fcnt0, fcnt1, _] = self.header;
        self.header = [mhdr, addr0, addr1, addr2, addr3, fctrl, fcnt0, fcnt1, frame_port];
    }

    /// The payload bytes
    pub fn payload(&self) -> &[u8] {
        // Note: The payload length is assumed to be valid here
        #[allow(clippy::indexing_slicing, reason = "Length should always be valid")]
        &self.payload[..self.payload_len]
    }
    /// The payload bytes
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // Note: The payload length is assumed to be valid here
        #[allow(clippy::indexing_slicing, reason = "Length should always be valid")]
        &mut self.payload[..self.payload_len]
    }
    /// Returns the payload as a tuple with the buffer and the amount of bytes in there (aka payload length)
    pub fn into_payload(self) -> ([u8; MAX_PAYLOAD_SIZE], usize) {
        (self.payload, self.payload_len)
    }

    /// The MIC bytes
    pub fn mic(&self) -> &[u8; Self::MIC_SIZE] {
        &self.mic
    }
    /// The MIC bytes
    pub fn mic_mut(&mut self) -> &mut [u8; Self::MIC_SIZE] {
        &mut self.mic
    }
}
