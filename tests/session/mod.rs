//! A mock session implementation

use loreyawen::{Direction, SessionState};

/// A mock session object
#[derive(Debug, Clone, Copy)]
pub struct MockSession {
    /// The network session key
    pub nwkskey: [u8; 16],
    /// The application session key
    pub appskey: [u8; 16],
    /// The end-device address
    pub device_address: u32,
    /// The frame counter for uplink frames
    pub frame_counter_uplink: u32,
    /// The frame counter for downlink frames
    pub frame_counter_downlink: u32,
}
impl SessionState for &mut MockSession {
    fn nwkskey(&self) -> [u8; 16] {
        self.nwkskey
    }

    fn appskey(&self) -> [u8; 16] {
        self.appskey
    }

    fn device_address(&self) -> u32 {
        self.device_address
    }

    fn frame_counter(&self, direction: Direction) -> u32 {
        match direction {
            Direction::Uplink => self.frame_counter_uplink,
            Direction::Downlink => self.frame_counter_downlink,
        }
    }

    fn set_frame_counter(&mut self, counter: u32, direction: Direction) {
        match direction {
            Direction::Uplink => self.frame_counter_uplink = counter,
            Direction::Downlink => self.frame_counter_downlink = counter,
        }
    }
}
