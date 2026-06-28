# EDP Prior Art and Related Work

EDP sits at the intersection of entropy distribution, embedded systems security,
and mesh networking. This document surveys the relevant prior work that informed
the design and establishes where EDP diverges.

---

## Directly related work

| Reference | What it does | How EDP differs |
|-----------|-------------|-----------------|
| arXiv:2603.09311 (2026) | External entropy supply for IoT devices via a RISC-V TEE-backed server | Client-server model; EDP is peer-to-peer. No single entropy server. |
| arXiv:2603.10274 / QEaaS (2026) | QRNG entropy from Quantis device to ESP32-class clients over post-quantum-secured channels | Client-server with expensive QRNG hardware; EDP works with commodity sensors |
| ACM 10.1145/3799895 (2026) | Remote QRNG shared via D-Bus on a single host | Single-host, not networked mesh |
| drand (Cloudflare et al.) | Distributed randomness beacon via threshold BLS signatures | Internet-scale, server infrastructure; not embedded, not peer mesh |
| Linux `/dev/random` pooling | Kernel gathers entropy from hardware events into a CSPRNG | Single-host; EDP is a complement, not a replacement |

**The key gap EDP addresses:** all surveyed entropy distribution solutions use
a client-server model. The client requests entropy from a trusted server. EDP
is the first proposal (to the authors' knowledge as of June 2026) for a fully
peer-to-peer closed-loop embedded mesh where every node is both producer and
consumer, and the failure mode when any node goes down is graceful degradation
rather than loss of entropy service.

---

## Foundational references

**RFC 4086** -- Eastlake, Schiller, Crocker, "Randomness Requirements for Security,"
IETF, June 2005. The canonical reference for why entropy matters in security
systems and how to think about entropy sources. Port 4086 is an homage to this
document.

**NIST SP 800-90B** -- Turan et al., "Recommendation for the Entropy Sources Used
for Random Bit Generation," NIST, January 2018. The methodology for measuring and
validating entropy sources. EDP's Tier classification is designed to be consistent
with 800-90B terminology, but no formal 800-90B assessments of EDP sources have
been conducted.

**NIST SP 800-90A** -- Barker, Kelsey, "Recommendation for Random Number Generation
Using Deterministic Random Bit Generators." Provides context for CSPRNG design;
EDP's pool is not itself a DRBG in the 800-90A sense.

**BLAKE3** -- O'Connor et al., "BLAKE3: One Function, Fast Everywhere," 2020.
The hash function used for all EDP pool mixing and entropy conditioning. Chosen
for speed on RISC-V (~10× SHA-256), simplicity (~1400 lines portable C), and
the keyed and XOF modes it provides.

**Monocypher** -- Dubedat, "Monocypher: Easy to Use, Easy to Deploy Cryptography."
Used for Ed25519 node identity. Chosen for its small footprint (~2000 lines portable
C), no dynamic allocation, and BSD-2-Clause license.

---

## What EDP does not cite as prior art (to avoid confusion)

EDP is not related to:

- Entropy compression or data compression algorithms.
- Blockchain randomness beacons (VDF-based or otherwise).
- Trusted Execution Environment (TEE) attestation protocols, though a TEE
  could be used to secure EDP key storage.
- Physical unclonable functions (PUFs), though PUF output could be used as
  a Tier 0 entropy source.

---

## Citation

If you use EDP in academic work, please cite:

```
Hydrogenuine Project, "EDP: Entropy Distribution Protocol for Embedded
Peer Meshes," v0.1-DRAFT, June 2026.
https://github.com/andrew867/EDP
```
