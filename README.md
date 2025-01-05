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
`0b111`-prefixed) LoRaWAN frames. Messages are encrypted using AES-CTR using the `appskey`, and packed into this minimal
LoRaWAN frame and authenticated using AES-CMAC using the `nwkskey`. See `TS001-1.0.4 LoRaWAN® L2 1.0.4 Specification`
for more information on the LoRaWAN link-layer encryption.


## Security Considerations and Notes
This implementation assumes that a unique and random `appskey` and `nwkskey` are _somehow_ deployed out-of-band in
secure fashion. Those keys are used to encrypt and authenticate messages in an "accidentally" LoRaWAN compatible way;
however it does not implement any other LoRaWAN semantics like media access control or session rekeying/reset.

This means, `loreyawan` is _not_ affected by the common LoRaWAN security vulnerabilities. LoRaWAN's basic link-layer, as implemented by this crate, is a pretty simple packetcounter-encrypt-mac scheme, which is considered reasonably secure.
Also, `loreyawen` optionally truncates the MIC to 64 bit instead of just 32 bit, as the security benefit might be
significant, and the overhead is usually negligible.


## Dependency and Interoperability with LoRa(WAN)
`loreyawen` frames are marked as proprietary LoRaWAN frames, which indicates to the receiver that this are not standard
frames. Compliant receivers should recognize this and treat the frames accordingly.

While `loreyawen` masquerades as LoRaWAN proprietary frames, it can actually be used completely indepently of an
existing LoRaWAN session or LoRa(WAN) at all. Once the keys are deployed, it can be just used as-is to provide an
encrypted link between server and end-device, without any higher level LoRaWAN logic and associated vulnerabilities.
`loreyawen` can even be used with completely different physical networks, since it does not rely on any LoRa-specific
parts.


## Frame Format and Deviations from LoRaWAN Uplink/Downlink Frames
`loreyawen` uses a LoRaWAN-proprietary frame format, with the following fields:
- 1 byte `MHDR`, fixed to `0b111_000_00` (indicates a "proprietary" frame for LoRaWAN version 1.0)
- 8 bytes `FHDR`, consisting of 4 bytes `DevAddr`, 1 byte `FCtrl`, 2 bytes `FCnt`, and 1 byte `FPort`
- N bytes encrypted payload
- 4 or 8 bytes `MIC` (which is just a less-truncated version of the default LoRaWAN MIC)

```ascii
Loreyawen Frame:
MHDR[1] | DevAddr[4] | FCtrl[1] | FCnt[2] |     FOpts[0] |    FPort[1] | Payload[N] | MIC[4 or 8]

LoRaWAN Uplink/Downlink Frame as Reference:
MHDR[1] | DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] | FPort[0..1] | Payload[N] | MIC[4]
```

This format is pretty similar to the regular uplink/downlink frames. The `FOpts` field is always ommitted, while the
`FCtrl` and `FPort` field can be used to transmit application specific plaintext values. If the `extended-mic` feature
is enabled, the MIC is truncated to 64 bit, instead of the 32 bit from default LoRaWAN.
