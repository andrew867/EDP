# EDP Protocol Limitations

**Status:** 0.1-DRAFT. This document is deliberately honest. If a limitation
is listed here, it means the current prototype does not solve it.

---

## Implementation limitations

**PTP sync not implemented.** EPOCH_SYNC uses a local monotonic clock fallback.
True PTP-synchronized epoch injection requires a PTP daemon and kernel timestamping
hooks that are not in the current implementation.

**Benchmark not implemented.** `tests/bench.c` is a stub. Measured throughput
numbers for BLAKE3 mixing and Ed25519 verification on target hardware (Kendryte
K230, Sipeed LM4A) are not yet available.

**QEMU/hardware integration tests not complete.** The integration test script
(`tests/test_integration.sh`) runs the daemon in loopback mode on Linux. The
QEMU RISC-V path is stubbed but not validated.

**No key rotation.** The current design supports REVOKE + new HELLO as the
rotation mechanism, but there is no automated rotation schedule or revocation
distribution protocol.

**No kernel entropy injection on all targets.** The `inject_to_kernel` callback
in `edp_config_t` is designed for Linux's `getrandom`/`/dev/random` injection
interface. Integration with RISC-V bare-metal targets is not implemented.

---

## Protocol limitations

**Port 4086 is not IANA-assigned.** IANA lists 4086/tcp as Reserved. EDP uses
4086 as an aspirational default (homage to RFC 4086 on randomness requirements).
Any deployment should either use a port in the dynamic/private range (49152–65535)
or obtain a formal IANA assignment.

**UDP multicast has no transport encryption.** Packet contents beyond the 64-byte
EC payload (which is conditioned entropy, not raw source data) are in the clear.
The protocol does not attempt to provide confidentiality at the transport layer.
Node IDs and public keys are visible to network observers.

**The Sybil delay (30 seconds) is not a strong defence.** It raises the cost of
a Sybil attack but does not prevent a patient adversary. A proper Sybil defence
requires out-of-band node provisioning, which EDP does not provide.

**No formal entropy accounting.** The `entropy_estimate` field in `edp_pool_t`
is a rough heuristic, not a formal min-entropy bound. It should not be used as
a reliable entropy guarantee.

---

## Entropy source limitations

**IMU thermal noise requires measurement.** The claim that IMU LSB noise produces
~1800 bits/s is a design estimate. Actual entropy depends on the sensor model,
PCB layout, and operating conditions. Measure with NIST SP 800-90B before
assigning to a trust tier.

**Encoder jitter requires measurement.** Similar caveat. Claimed ~150–200 bits/s
is an estimate. High-quality encoders with clean power may produce much less jitter
than assumed.

**CAN FD timing entropy requires measurement.** Bus timing jitter depends on
network topology, termination, and load. Do not assume this source is reliable
without measurement.

**HAVEGE timing source is software-only.** On systems with constant-time CPU
features or in virtualized environments, HAVEGE may produce little real entropy.
It is listed as Tier 3 (lowest) for this reason.

**FPGA TRNG is a prototype.** The ring-oscillator TRNG in `fpga/trng_core.v`
has not been synthesised and tested on real silicon. Startup bias, temperature
effects, and correlation between the two ring oscillators need measurement before
any trust tier assignment is meaningful. NIST SP 800-90B reports are planned but
not yet conducted.

---

## Claims that are not made

- EDP does not guarantee entropy improvement in the pool. It aims to prevent
  reduction. Whether remote contributions actually add usable entropy depends on
  the source measurement and threat model.
- EDP is not a replacement for a local hardware TRNG or the Linux kernel CSPRNG.
- EDP is not FIPS-certified, NIST-certified, or independently audited.
- EDP is not IETF-standardized. The draft IETF submission is aspirational.
- EDP has not been reviewed for export control compliance. Consult a lawyer
  before distributing in jurisdictions with cryptography export restrictions.
