//! Session and state management types

/// A message direction
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Direction {
    /// An uplink message from the end-device to the server
    Uplink = 0,
    /// A downlink message from the server to the end-device
    Downlink = 1,
}

/// A loreyawen session state
pub trait SessionState {
    /// The network session key used to authenticate packets
    fn nwkskey(&self) -> &[u8; 16];
    /// The application session key used to encrypt payloads
    fn appskey(&self) -> &[u8; 16];
    /// The device address
    fn device_address(&self) -> u32;

    /// The frame counter for packets with the given direction
    fn frame_counter(&self, direction: Direction) -> u32;
    /// Sets the frame counter for packets with the given direction
    fn set_frame_counter(&mut self, counter: u32, direction: Direction);
}

/// Helper type to help implement `SessionState` for any `&mut T where T: SessionState`
#[derive(Debug)]
pub struct SessionRefMut<'a, T> {
    /// The underlying session
    session: &'a mut T,
}
impl<'a, T> SessionRefMut<'a, T> {
    /// Creates a new session reference
    pub const fn new(session: &'a mut T) -> Self {
        Self { session }
    }
}
impl<T> SessionState for SessionRefMut<'_, T>
where
    T: SessionState,
{
    fn nwkskey(&self) -> &[u8; 16] {
        self.session.nwkskey()
    }
    fn appskey(&self) -> &[u8; 16] {
        self.session.appskey()
    }
    fn device_address(&self) -> u32 {
        self.session.device_address()
    }
    fn frame_counter(&self, direction: Direction) -> u32 {
        self.session.frame_counter(direction)
    }
    fn set_frame_counter(&mut self, counter: u32, direction: Direction) {
        self.session.set_frame_counter(counter, direction)
    }
}
