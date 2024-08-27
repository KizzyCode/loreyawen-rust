[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/loreyawen-rust?svg=true)](https://ci.appveyor.com/project/KizzyCode/loreyawen-rust)
[![docs.rs](https://docs.rs/loreyawen/badge.svg)](https://docs.rs/loreyawen)
[![crates.io](https://img.shields.io/crates/v/loreyawen.svg)](https://crates.io/crates/loreyawen)
[![Download numbers](https://img.shields.io/crates/d/loreyawen.svg)](https://crates.io/crates/loreyawen)
[![dependency status](https://deps.rs/crate/loreyawen/latest/status.svg)](https://deps.rs/crate/loreyawen)

# `loreyawen`
Welcome to `loreyawen` 🎉

`loreyawen` provides an encrypted "connection" for low-datarate networks by piggybacking on LoRaWANs link encryption. 
This crate uses an existing or artificially botstrapped LoRaWAN session to pack payloads into "proprietary" (aka
`0b111`) LoRaWAN frames. Messages are encrypted using AES-CTR using the `appskey`, and packed into this minimal LoRaWAN
frame and authenticated using AES-CMAC using the `nwkskey`. See `TS001-1.0.4 LoRaWAN® L2 1.0.4 Specification` for more
information on the LoRaWAN link-layer encryption.

## Security Considerations and Notes
This implementation assumes that a unique and random `appskey` and `nwkskey` are _somehow_ deployed out-of-band in
secure fashion. Those keys are used to encrypt and authenticate messages in an "accidentally" LoRaWAN compatible way;
however it does not implement any high-level LoRaWAN semantics like media access control or session rekeying/reset.

This means, `loreyawan` is _not_ affected by the higher-level LoRaWAN security vulnerabilities during session
setup/reset etc; LoRaWAN's basic link-layer as implemented by this crate is considered reasonably secure in low-datarate
networks.

Furthermore, this also means that this crate can actually be used completely indepently of an existing LoRaWAN session
or LoRa(WAN) at all: once the keys are deployed, it can be just used as-is to provide an encrypted link between a server
and an end-device, without any higher level LoRaWAN logic and vulnerabilities.

## Frame Format
`loreyawen` uses a LoRaWAN-proprietary frame format, with the following fields:
- 1 byte `MHDR`, fixed to `0b111_000_00`
- 7 bytes `FHDR`, consisting of 1 byte `Version`, 4 bytes `DevAddr`, and 2 bytes `FCnt`
- N bytes payload
- 4 bytes `MIC`, which is the default 32 bit LoRaWAN MIC

```ascii
MHDR[1] | Version[1] | DevAddr[4] | FCnt[2] | Payload[N] | MIC[4]
```

This format is pretty similar to the regular uplink/downlink frames. The unused `FCtrl` and `FOpts` fields are ommitted,
and we introduce a `Version` field to indicate this protocol version (`0x01` for this version).

The resulting frames should be compatible within an existing LoRaWAN environment as they are marked as proprietary,
indicating they are not standard frames and the MAC payload must be treated specially.
