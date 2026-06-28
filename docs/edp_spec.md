# EDP — Entropy Distribution Protocol
## Specification, Security Model, and Test Plans
**Version:** 0.1-DRAFT  
**Date:** 2026-06-18  
**Companion to:** IEEE 1588 PTP (Precision Time Protocol), DOCS OCU Architecture  
**Status:** Pre-standardization / Research Draft

---

## 1. Problem Statement

Embedded systems in closed-loop environments (no internet connectivity, fixed physical mesh) suffer from entropy starvation — particularly at boot time and after node resets. Existing solutions fall into two categories:

**Local hardware sources** (TRNGs, timing jitter, thermal noise) — adequate when the hardware includes a quality TRNG, but not all OCU classes will, and freshness degrades during idle periods.

**Client-server models** (QEaaS, RISC-V TEE entropy servers, drand) — require a trusted central entropy server. This introduces a single point of failure incompatible with the DOCS fault-tolerance model, and doesn't exploit the rich physical entropy sources distributed across the mesh (motor encoder jitter, IMU noise, audio DSP, CAN bus timing variance, etc.).

**The gap:** No standardized lightweight protocol exists for peer-to-peer entropy distribution in a closed-loop embedded mesh where:
- Every node is simultaneously a producer and consumer
- Physical sensor activity is a first-class entropy source
- The mesh survives node failures without losing entropy supply
- External entropy augments but never replaces local entropy (poisoning resistance)

EDP fills this gap.

---

## 2. Prior Art and Differentiation

| System | Model | Peer-to-peer? | Sensor entropy? | Closed-loop? | Fault-tolerant mesh? |
|---|---|---|---|---|---|
| drand | Threshold BLS beacon | No (committee) | No | No (internet) | Partial |
| QEaaS (arXiv 2603.10274) | QRNG server → clients | No | No | Yes | No |
| RISC-V TEE entropy supply (arXiv 2603.09311) | TEE server → IoT fleet | No | Partial | Yes | No |
| Remote QRNG via D-Bus (ACM 2026) | Single-host IPC | No | No | Yes | No |
| **EDP (this spec)** | **Peer mesh** | **Yes** | **Yes** | **Yes** | **Yes** |

EDP is not a replacement for hardware TRNGs or local entropy daemons. It is an entropy augmentation layer that enriches every node's entropy pool using contributions from the mesh.

---

## 3. Design Principles

**P1 — Augmentation only, never replacement.** External entropy is XOR-mixed into the local pool. An adversary controlling all remote nodes cannot reduce a node's entropy below its local source floor.

**P2 — Physical entropy is first-class.** Sensor readings (IMU noise, encoder jitter, audio DSP residuals, thermal sensors) are valid, high-quality entropy sources in a running embedded system. EDP provides a standard interface for registering and advertising these sources.

**P3 — FPGA TRNG is privileged.** FPGA ring-oscillator TRNGs are hardware-attested and cannot be manipulated by software. EDP assigns them the highest source quality tier.

**P4 — Lightweight.** EDP must run on RISC-V E-class cores (RV32IMC, 200 MHz, < 64 KB RAM). No threshold BLS, no pairing-based crypto, no Go runtime. UDP + BLAKE3 + X25519.

**P5 — PTP-aware.** EDP can use PTP-synchronized time windows to coordinate entropy injection across the mesh, allowing all nodes to seed their CSPRNGs from the same mesh entropy epoch simultaneously. This is optional and gracefully degrades without PTP.

**P6 — No trust hierarchy.** Every node has equal status. There is no master entropy server. If Agent Zero goes offline, entropy continues flowing.

---

## 4. Terminology

| Term | Definition |
|---|---|
| **Entropy Contribution (EC)** | A packet of conditioned entropy bytes from one node, ready for mixing |
| **Entropy Pool** | The local node's CSPRNG state (Linux kernel getrandom pool or equivalent) |
| **Source Quality Tier** | Classification of an entropy source (see Section 6) |
| **Conditioning** | Processing raw entropy through a hash or DRBG to produce uniform output |
| **Poisoning resistance** | The property that injecting predictable external entropy cannot weaken a node's pool |
| **Entropy epoch** | A PTP-synchronized window in which all nodes inject received entropy simultaneously |
| **Health score** | A per-source metric estimating entropy rate and freshness |

---

## 5. Protocol Overview

EDP operates in three phases per cycle:

```
PHASE 1 — HARVEST (local, continuous)
  Each node collects raw entropy from its registered sources.
  Raw bytes are conditioned through BLAKE3 keyed hash.
  Conditioned entropy accumulates in a local staging buffer.

PHASE 2 — BROADCAST (mesh, periodic)
  Every BROADCAST_INTERVAL (default: 1 second), each node:
    1. Packs a conditioned Entropy Contribution (EC) from its staging buffer.
    2. Signs EC with its node identity key (Ed25519).
    3. Multicasts EC to all mesh peers over UDP.

PHASE 3 — MIX (local, on receive)
  On receiving an EC from a peer:
    1. Verify Ed25519 signature against known peer identity.
    2. Reject if source quality tier is UNKNOWN or UNTRUSTED.
    3. Mix: local_pool = BLAKE3(local_pool || ec.entropy_bytes || ec.source_metadata)
    4. Feed mixed bytes into kernel entropy pool via getrandom/ioctl or equivalent.
    5. Update peer's health score in local node table.
```

The critical security property: step 3 XORs (via BLAKE3 chaining) the external EC with the existing local pool. Even if `ec.entropy_bytes` is all zeros or adversarially chosen, `BLAKE3(local_pool || zeros)` is indistinguishable from `BLAKE3(local_pool || good_entropy)` to an attacker who does not know `local_pool`. The local pool is never reset to the external value.

---

## 6. Entropy Source Quality Tiers

Sources are classified at registration time. Tier affects how received contributions are weighted (higher-tier contributions are mixed at higher volume; lower-tier at lower volume as a hedge).

| Tier | Name | Examples | Bits/s estimate | Attestation |
|---|---|---|---|---|
| 0 | FPGA_TRNG | Ring oscillator TRNG in FPGA fabric | 1–100 Mbit/s | Hardware (FPGA bitstream signature) |
| 1 | HARDWARE_TRNG | CPU TRNG (e.g., Seed CSR on RISC-V) | 1–10 Mbit/s | CPU architectural |
| 2 | SENSOR_PHYSICAL | IMU noise, encoder jitter, microphone thermal, CAN bus timing | 100–10K bit/s | Software-declared, heuristically validated |
| 3 | TIMING_JITTER | Execution timing jitter (haveged-style) | 10–1K bit/s | Software-declared |
| 4 | CSPRNG_RESEED | Output of a local CSPRNG after mixing | N/A | Derived |
| 5 | UNKNOWN | Unregistered or unverified source | — | Rejected |

Tier 0 and Tier 1 are hardware-attested. A node claiming Tier 0 without an FPGA-attested bitstream signature is downgraded to UNKNOWN and rejected.

---

## 7. Packet Formats

### 7.1 Entropy Contribution (EC) Packet

Sent by every node every BROADCAST_INTERVAL. Multicast to `224.0.EDP.1` (TBD IANA assignment) on UDP port 3140 (proposed; ref: Claude Shannon b. 1916 → 1916 mod 2048 = 1916... let's go with 4086 as homage to RFC 4086 on randomness requirements, or simply request assignment).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (4) | Type (4)      | Source Tier   | Reserved        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Node ID (32-bit, from OTP)                                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Sequence Number (32-bit, monotonic)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| PTP Timestamp (64-bit, nanoseconds since epoch, 0 if no PTP) |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entropy Byte Count (16-bit)   | Health Score (16-bit, 0-1000) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entropy Bytes (variable, 32–256 bytes)                        |
| ...                                                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ed25519 Signature (64 bytes)                                  |
| ...                                                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Type values:**
- `0x1` — EC (Entropy Contribution)
- `0x2` — HELLO (node announcement, carries public key)
- `0x3` — HEALTH (health-only update, no entropy bytes)
- `0x4` — EPOCH_SYNC (PTP-synchronized injection trigger)
- `0x5` — REVOKE (node is declaring its own key compromised)

### 7.2 HELLO Packet

Broadcast on node startup and every HELLO_INTERVAL (default: 30 seconds).

```
Node ID (32-bit) | Ed25519 Public Key (32 bytes) | Source Tiers Bitmap (8-bit) |
Capabilities (16-bit flags) | Firmware Hash (32 bytes, BLAKE3 of OCU firmware) |
Ed25519 Signature over above fields
```

Capabilities flags: `0x01` = PTP-capable, `0x02` = FPGA-TRNG present, `0x04` = RISC-V Seed CSR present, `0x08` = sensor array present.

### 7.3 Key Management

- Each OCU generates its Ed25519 identity keypair at first boot, stored in TEE or secure flash.
- Public keys are distributed via HELLO packets and cached in each node's peer table.
- Key rotation: a node can sign a new public key with the old private key before rotating.
- Revocation: `REVOKE` packet signed with current key; all peers drop that node's contributions.
- There is no PKI or CA. Trust is mesh-local: nodes trust peers whose HELLO they received on the local bus. An OCU on a different physical bus segment is not automatically trusted.

---

## 8. Entropy Harvesting — Source Integration

### 8.1 FPGA TRNG (Tier 0)

Implement a ring-oscillator TRNG in FPGA fabric. Two or more free-running ring oscillators with different delays; sample XOR of their outputs at a third clock domain to harvest thermal jitter. Standard approach, well-documented in Lattice and Xilinx application notes.

Output via narrow FIFO to RISC-V memory-mapped interface. EDP harvester reads FIFO at 10 ms intervals, conditions output with BLAKE3.

Minimum target: 1 Mbit/s raw, ≥ 0.5 bits entropy per raw bit after NIST SP 800-90B estimation.

### 8.2 Sensor Physical Entropy (Tier 2)

| Sensor | Entropy extraction method | Notes |
|---|---|---|
| IMU (accel/gyro) | LSBs of readings at rest; difference from predicted value | ~50–200 bits/s |
| Motor encoder | Timing jitter of index pulses | Higher entropy when motor is running |
| CAN FD bus | Frame arrival timing jitter | ~100 bits/s typical |
| Microphone | Thermal noise floor (no sound) | DSP OCU only; ~1 Kbit/s |
| Thermal sensors | Temperature LSB noise | Very slow; ~1 bit/s, useful only for seeding |
| NPU execution timing | Cycle count jitter in matrix ops | ~10–50 bits/s |

Raw readings are passed through a von Neumann corrector or BLAKE3 conditioning before entering the staging buffer.

### 8.3 RISC-V Seed CSR (Tier 1)

RISC-V Zkt extension defines a `seed` CSR that returns 16 bits of entropy per read with a status code (ES16 = ready, BIST = self-test, WAIT = not ready, DEAD = failed). EDP polls Seed CSR at startup and during idle periods. DEAD state triggers a source health alert.

### 8.4 Timing Jitter (Tier 3)

Port of haveged-style HAVEGE algorithm: execute a fixed code block with unpredictable branch behavior, measure cycle counter delta. Usable on any RISC-V core with a cycle counter (`rdcycle`). Quality is lower than hardware sources; used as fallback.

---

## 9. PTP Integration (Optional)

When PTP is running on the organ bus:

1. The PTP grandmaster broadcasts an EPOCH_SYNC EDP packet at the start of each entropy epoch (default: every 60 seconds).
2. EPOCH_SYNC carries the PTP-synchronized timestamp for the epoch start.
3. All nodes inject their accumulated received EC bytes into their kernel pools simultaneously at epoch start.
4. This ensures that if the same secret is derived from entropy pool state on multiple OCUs within the same epoch, they have the maximum possible entropy diversity (they mixed the same mesh contributions at the same time from different local pools).

Without PTP: nodes inject received EC bytes immediately on receipt (Phase 3 as described). Slightly less coordinated but functionally fine.

---

## 10. Security Analysis

### 10.1 Entropy Poisoning Resistance

An adversary controlling k out of n mesh nodes cannot predict the entropy pool of an honest node p. Because:

```
pool_p = BLAKE3(pool_p_local || EC_1 || EC_2 || ... || EC_n)
```

`pool_p_local` is seeded by p's own hardware/sensor sources. The adversary does not know `pool_p_local`. Therefore `pool_p` is unpredictable to the adversary regardless of what EC values the adversary supplies.

Formal claim: EDP is entropy-augmenting-secure if the local entropy source provides at least k_min bits of entropy (k_min recommended: 128 bits minimum from hardware sources). The protocol degrades gracefully as local sources degrade; it does not fail silently.

### 10.2 Replay Attacks

EC packets carry a monotonic sequence number. Nodes reject packets with sequence numbers equal to or less than the last received sequence number from that Node ID. A replayed old EC packet is dropped.

### 10.3 Spoofing

EC packets are Ed25519-signed. An adversary cannot spoof a legitimate node's contributions without its private key.

### 10.4 Sybil Attack

New nodes must send a HELLO packet and be observed for at least one HELLO_INTERVAL before their EC contributions are accepted. This doesn't prevent a well-resourced attacker from inserting a physical node, but it limits drive-by injection. In DOCS context, the physical bus is assumed to be within a controlled chassis — physical access is the threat boundary.

### 10.5 Denial of Service (Entropy Flooding)

A malicious node could send EC packets at high frequency, consuming CPU time for signature verification. Mitigation: rate-limit incoming EC packets per source node to 2x BROADCAST_INTERVAL minimum. Excess packets are dropped without signature verification.

### 10.6 Source Tier Fraud

A node claiming Tier 0 (FPGA TRNG) without attestation evidence is downgraded to UNKNOWN. Attestation: the FPGA bitstream is signed; its hash is included in the HELLO packet firmware hash. A verifying node can check that the claimed FPGA capability matches the known-good firmware hash for that OCU class.

---

## 11. Implementation Requirements

### 11.1 Mandatory

- UDP multicast on the organ bus
- Ed25519 key generation and signing at first boot
- HELLO/EC/HEALTH packet generation and parsing
- At least one Tier 0, 1, 2, or 3 entropy source registered
- BLAKE3 conditioning of all raw entropy before staging
- XOR-mix received EC bytes into kernel entropy pool
- Per-node sequence number tracking (replay prevention)
- Rate limiting of incoming EC packets

### 11.2 Optional

- PTP EPOCH_SYNC support
- FPGA TRNG integration (Tier 0)
- RISC-V Seed CSR (Tier 1)
- Physical sensor entropy harvesting (Tier 2)
- REVOKE packet support (key compromise recovery)
- Health dashboard reporting to Agent Zero

### 11.3 Resource Budget (target)

| Resource | Target |
|---|---|
| RAM (daemon + buffers) | < 64 KB |
| Flash (daemon binary) | < 128 KB |
| CPU (E-core, 200 MHz) | < 2% average, < 10% burst |
| Network | < 2 KB/s per node outbound |
| Crypto operations | Ed25519 sign: < 5 ms on E-core |

---

## 12. Test Plans

### 12.1 Source Quality Tests

| Test ID | Name | Method | Pass Criteria |
|---|---|---|---|
| SRC-01 | FPGA TRNG output rate | Read FIFO at 10ms intervals for 60s; count bytes | > 100 KB/s raw output |
| SRC-02 | FPGA TRNG entropy estimation | Run NIST SP 800-90B IID tests on 1 MB sample | Entropy estimate > 0.9 bits/bit |
| SRC-03 | Seed CSR availability | Poll 1000x; count ES16 responses | > 90% ES16 (ready) responses |
| SRC-04 | IMU entropy rate | Collect 10s of IMU LSBs at rest; run ENT analysis | > 50 bits/s estimated entropy |
| SRC-05 | Encoder jitter entropy | Collect 10s of encoder timing jitter; run ENT | > 20 bits/s during motor run |
| SRC-06 | Timing jitter (HAVEGE) | Run for 30s, collect output | > 10 bits/s; passes ENT monobit test |
| SRC-07 | BLAKE3 conditioning output | Condition 1000 samples of known-low-entropy input | Output passes NIST SP 800-22 test suite |

### 12.2 Protocol Correctness Tests

| Test ID | Name | Method | Pass Criteria |
|---|---|---|---|
| PROT-01 | HELLO packet broadcast on boot | Monitor multicast; capture first packet | Received within 5s of boot; valid signature |
| PROT-02 | EC packet cadence | Monitor for 60s | EC received every 1.0s ± 0.1s per node |
| PROT-03 | Signature verification | Inject EC packet with wrong signature | Packet rejected; no pool mix |
| PROT-04 | Replay detection | Replay a captured EC packet | Packet rejected (sequence number check) |
| PROT-05 | Source tier fraud detection | Claim Tier 0 without attestation | Downgraded to UNKNOWN; contribution rejected |
| PROT-06 | Rate limiting | Flood 100 EC packets/s from one node | All but 2/s are dropped without verification |
| PROT-07 | Revocation propagation | Send REVOKE from node N | All peers stop accepting N's EC within 3s |

### 12.3 Security Tests

| Test ID | Name | Method | Pass Criteria |
|---|---|---|---|
| SEC-01 | Poisoning resistance | All remote nodes send all-zeros entropy | Recipient pool entropy does not degrade vs. local-only baseline |
| SEC-02 | Pool independence | Two nodes with identical CSPRNG seeds + different physical sources | Their pools diverge within 10 entropy epochs |
| SEC-03 | Key isolation | Extract E-core RAM; search for Ed25519 private key | Key not found in non-TEE RAM |
| SEC-04 | Sybil delay | Connect new node; send EC immediately | First 30s of EC contributions rejected |
| SEC-05 | Spoofed HELLO | Inject HELLO claiming existing Node ID with different key | HELLO rejected; existing key retained |
| SEC-06 | Pool strength after node loss | Kill Tier 0 FPGA TRNG source; monitor pool health score | Pool health degrades gracefully; no crash; fallback sources activate |

### 12.4 Integration Tests (DOCS Mesh)

| Test ID | Name | Method | Pass Criteria |
|---|---|---|---|
| INT-01 | Full mesh entropy exchange | Boot all 6 OCUs; monitor for 5 minutes | Every node shows received EC from every other node |
| INT-02 | Boot-time entropy availability | Measure time until /dev/random unblocked after cold boot | < 5s on all OCU types |
| INT-03 | Entropy diversity post-mix | Compare pool states across nodes after 60s | No two pools have identical state (compare getrandom(32) samples) |
| INT-04 | PTP epoch sync | Enable PTP; trigger EPOCH_SYNC; confirm all nodes inject at same millisecond | All nodes log epoch injection within 10ms of each other |
| INT-05 | Node failure, entropy continuity | Kill one OCU mid-operation | Remaining nodes continue EC broadcast; no entropy gaps |
| INT-06 | Network partition, entropy isolation | Partition mesh into two groups for 60s | Each partition maintains entropy independently; no crash |
| INT-07 | Cryptographic quality post-EDP | Generate 10,000 TLS key pairs on each OCU after 60s of EDP | All keys pass NIST SP 800-22; no weak keys detected |

### 12.5 Performance Tests

| Test ID | Metric | Target | Method |
|---|---|---|---|
| PERF-01 | EC packet processing latency | < 5 ms per packet (E-core) | Timestamp before/after parse+verify+mix |
| PERF-02 | Ed25519 sign latency | < 5 ms on E-core @ 200 MHz | Microbenchmark 1000 iterations |
| PERF-03 | BLAKE3 conditioning throughput | > 1 MB/s on E-core | Benchmark 10 MB input |
| PERF-04 | Daemon RAM usage | < 64 KB | /proc/self/status RSS after 60s |
| PERF-05 | Network overhead | < 2 KB/s outbound | tcpdump + byte count over 60s |
| PERF-06 | CPU utilization | < 2% average on E-core | top/htop over 5 min |

---

## 13. Open Questions and Risk Items

| # | Question / Risk | Severity | Notes |
|---|---|---|---|
| 1 | IANA port assignment for EDP | Low | Use ephemeral port for prototype; seek assignment on standardization |
| 2 | NIST SP 800-90B estimation of sensor sources | High | Estimation is difficult; may overestimate entropy rate from sensors |
| 3 | Ed25519 sign on RV32 E-core at 200 MHz — latency budget | High | Need to benchmark; may need pre-computation or use E-core only for broadcast |
| 4 | BLAKE3 availability on RISC-V embedded toolchains | Medium | Reference implementation exists; verify it builds for RV32IMC without FPU |
| 5 | Physical sensor entropy correlation | Medium | IMU noise on adjacent nodes in same chassis may be correlated (shared vibration); reduces effective entropy diversity |
| 6 | Interaction with Linux kernel getrandom vs. /dev/random | Medium | Kernel 5.17+ unified the two; but embedded kernels may be older |
| 7 | TEE availability on target SoCs for key storage | Medium | K230 and LM4A have TEE support; verify keystore API |
| 8 | Multicast routing on 2.5GbE managed switch | Low | Enable IGMP snooping; test multicast reach across VLAN if segmented |
| 9 | PTP grandmaster election stability | Low | If PTP grandmaster changes mid-epoch, EPOCH_SYNC may be delayed; graceful fallback needed |
| 10 | Standardization path (IETF vs. IEEE) | Medium | PTP companion → IEEE 1588 WG. Embedded mesh → IETF ROLL WG. Or independent IETF RFC. |

---

## Appendix A — Reference Implementation Sketch (C, RISC-V E-core target)

```c
/* edp_harvest.c — minimal EDP entropy harvester */
#include <stdint.h>
#include <string.h>
#include "blake3.h"      /* BLAKE3 reference implementation */
#include "ed25519.h"     /* TweetNaCl or WolfSSL Ed25519 */

#define EDP_EC_ENTROPY_BYTES  64
#define EDP_UDP_PORT          4086

typedef struct {
    uint8_t  version_type;   /* upper 4: version=1, lower 4: type */
    uint8_t  source_tier;
    uint16_t reserved;
    uint32_t node_id;
    uint32_t sequence;
    uint64_t ptp_timestamp;
    uint16_t entropy_byte_count;
    uint16_t health_score;
    uint8_t  entropy[EDP_EC_ENTROPY_BYTES];
    uint8_t  signature[64];  /* Ed25519 */
} __attribute__((packed)) edp_ec_packet_t;

/* Harvest raw entropy from FPGA TRNG MMIO FIFO */
static int harvest_fpga_trng(uint8_t *buf, size_t len) {
    volatile uint32_t *fifo = (volatile uint32_t *)FPGA_TRNG_FIFO_BASE;
    volatile uint32_t *status = (volatile uint32_t *)FPGA_TRNG_STATUS;
    for (size_t i = 0; i < len / 4; i++) {
        while (!(*status & TRNG_READY)) {}  /* spin wait */
        ((uint32_t *)buf)[i] = *fifo;
    }
    return 0;
}

/* Condition raw bytes through BLAKE3 keyed hash */
static void condition_entropy(const uint8_t *raw, size_t raw_len,
                               const uint8_t *key, uint8_t *out, size_t out_len) {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    blake3_hasher_update(&h, raw, raw_len);
    blake3_hasher_finalize(&h, out, out_len);
}

/* Mix received EC into local pool via BLAKE3 chaining */
static void mix_into_pool(uint8_t *pool, size_t pool_len,
                           const uint8_t *ec_bytes, size_t ec_len,
                           const uint8_t *source_metadata, size_t meta_len) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pool, pool_len);
    blake3_hasher_update(&h, ec_bytes, ec_len);
    blake3_hasher_update(&h, source_metadata, meta_len);
    blake3_hasher_finalize(&h, pool, pool_len); /* in-place update */
    /* Feed into kernel pool */
    getrandom_inject(pool, pool_len);  /* platform-specific */
}
```

---

## Appendix B — Relationship to Claude Shannon

Claude Shannon's 1948 paper "A Mathematical Theory of Communication" defined entropy as a measure of information content and uncertainty. EDP applies this directly: the protocol's security rests on the entropy (unpredictability) of each node's local physical state. Shannon showed that you cannot transmit more information than the channel's capacity — EDP similarly cannot inject more entropy into a pool than the sum of the true entropy rates of all contributing sources. The protocol is honest about this: health scores are estimates, not guarantees, and the security model degrades gracefully rather than silently when source quality drops.

The proposed UDP port 4086 is a nod to RFC 4086 ("Randomness Requirements for Security"), which remains the canonical reference for why this problem matters.

---

*End of EDP Specification v0.1-DRAFT*
