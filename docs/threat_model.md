# EDP Threat Model

**Status:** 0.1-DRAFT — not formally verified.

## Scope

This document describes the threat model for the EDP peer mesh entropy
augmentation protocol. It covers what EDP is designed to resist, what it
cannot resist, and what remains unverified.

---

## Attacker model

EDP assumes a network-level attacker who can:

- Observe all UDP multicast traffic on the local mesh network.
- Replay previously seen EDP packets.
- Inject crafted EDP packets (with or without valid signatures).
- Operate Sybil nodes that join the mesh and send crafted entropy contributions.
- Control some fraction of the peers in the mesh, but not all.
- Choose adversarially the content of EC (entropy contribution) packets.

EDP does **not** assume the attacker:

- Has compromised the local node's hardware or software.
- Knows the local node's entropy pool state.
- Can observe the internal BLAKE3 pool state.

---

## Primary security invariant (proof sketch)

For each remote EC that passes verification:

```
pool_{t+1} = BLAKE3(pool_t || remote_tag || ec_entropy || metadata || tier_byte)
```

Since the local pool state `pool_t` is secret and BLAKE3 is modeled as a
random oracle, a fixed external `ec_entropy` does not allow an adversary to
predict or control `pool_{t+1}` without knowing `pool_t`. The mixing step
therefore should not reduce pool security under this model.

**This is a proof sketch, not a formal proof.** It relies on the random-oracle
assumption for BLAKE3, which is standard but not formally proven for any
concrete hash function.

---

## Protections in place

| Threat | Mitigation | Status |
|--------|------------|--------|
| Replay attack | Monotonic sequence number per peer; replays dropped | Implemented |
| Spoofing (crafted packets) | Ed25519 per-node identity; unverified packets dropped | Implemented |
| Sybil attack | 30-second delay before new peer EC accepted | Implemented |
| Rate flooding | Max 2 EC/second per peer accepted | Implemented |
| Tier fraud | Peer's claimed tier checked against announced capabilities | Implemented |
| Adversarial EC content | BLAKE3 mixing over secret local state | Implemented (proof sketch) |
| Node dropout | Peers marked OFFLINE after 3 missed heartbeats | Implemented |

---

## Known gaps and unverified claims

- **Source entropy quality:** The tier classification (Tier 0–3) is based on
  design assumptions, not measured entropy rates. IMU thermal noise, encoder
  jitter, and CAN FD timing need NIST SP 800-90B assessment to validate
  claimed entropy rates.

- **FPGA TRNG quality:** The ring-oscillator TRNG design has not been tested
  on real silicon. Metastability behaviour, bias, and autocorrelation need
  measurement.

- **Compromised majority:** If more than half the mesh peers are adversary-
  controlled, the mixing step still does not weaken an uncompromised local
  pool (by the invariant above), but it cannot guarantee meaningful entropy
  augmentation either.

- **Side channels:** The implementation does not protect against timing or
  power side-channels on the BLAKE3 or Ed25519 operations.

- **Transport security:** EDP uses UDP multicast with no transport-layer
  encryption. Packet contents (other than the 64-byte EC payload) are
  visible to network observers.

---

## Out of scope

- Physical hardware attacks on local entropy sources.
- Attacks that compromise the local OS or runtime.
- Denial of service against the UDP multicast network (EDP does not
  attempt to solve this).
- Long-term key compromise (there is currently no key rotation mechanism
  beyond REVOKE + HELLO with a new keypair).
