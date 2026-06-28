# Request for Proposals
## EDP — Entropy Distribution Protocol
### Reference Implementation for Embedded RISC-V Mesh Systems

**Issuing Organization:** Hydrogenuine (Project DOCS)  
**RFP Issue Date:** 2026-06-18  
**Proposal Deadline:** TBD  
**RFP Reference:** HYD-RFP-2026-001  
**Classification:** Public / Open Source Required

---

## 1. Executive Summary

Hydrogenuine is seeking proposals for the design and implementation of the **Entropy Distribution Protocol (EDP)**, a lightweight peer-to-peer entropy sharing protocol for closed-loop embedded mesh networks.

The intended deployment context is the DOCS (Distributed Organ Compute System) architecture: a humanoid android platform in which each anatomical subsystem (arm segments, legs, torso, head) runs an independent Organ Compute Unit (OCU) based on RISC-V heterogeneous compute with integrated FPGA programmable logic. OCUs communicate over a 2.5GbE backplane with a separate CAN FD safety bus.

EDP solves a real and unsolved problem: high-quality cryptographic randomness for embedded nodes in a closed-loop system with no internet connectivity, where every node simultaneously produces and consumes entropy from physical sensors and hardware TRNGs distributed across the mesh.

This is an open research and engineering problem. A paper describing the closest prior art was published in March 2026 (arXiv:2603.09311). No production implementation meeting all DOCS requirements exists. This RFP invites implementers — from academic research groups to embedded security firms — to propose solutions.

---

## 2. Background and Motivation

### 2.1 The Problem

Cryptographic security in embedded systems depends on the quality of available randomness. The DOCS platform faces three compounding challenges:

**Challenge 1 — Boot-time entropy starvation.** Each OCU boots from a cold or warm reset. The Linux kernel's entropy pool is empty or seeded only from weak sources (clock, MAC address). `getrandom()` blocks or returns weak bytes until sufficient entropy accumulates. This is a known, published problem (E-BOOT, IEEE 2020; "Welcome to the Entropics," IEEE 2013).

**Challenge 2 — Closed-loop isolation.** The DOCS chassis operates without internet connectivity. Standard solutions that rely on network time, external QRNG services, or internet-based randomness beacons (drand, NIST Randomness Beacon) are not available.

**Challenge 3 — Rich but untapped physical entropy.** A running android chassis is entropy-rich: IMU sensors (accelerometer, gyroscope) produce thermal noise; motor encoders produce timing jitter; CAN FD frames have timing variance; audio DSP has microphone thermal noise floor; FPGA fabric can host ring-oscillator TRNGs. None of this entropy is currently shared across OCU nodes.

### 2.2 What Exists

Recent published solutions address parts of this problem but not the full requirement:

| Solution | Gap |
|---|---|
| QEaaS — arXiv:2603.10274 (March 2026) | Client-server model; single entropy server is SPOF; no peer contribution |
| RISC-V TEE entropy supply — arXiv:2603.09311 (March 2026) | Same model; TEE server → IoT fleet; no physical sensor sources; not fault-tolerant |
| Remote QRNG via D-Bus — ACM TOPS 2026 | Single-host IPC only; not a network protocol |
| drand | Internet-dependent; threshold BLS is too heavyweight for E-core; not embedded |
| haveged | Single-node only; no distribution |

**The gap EDP fills:** a protocol where every node is a producer and consumer, physical sensor entropy is a first-class source, there is no single server, and the mesh continues functioning if any node fails.

### 2.3 Why This Matters Beyond DOCS

EDP addresses a gap that will become more acute as embedded AI proliferates:

- Robot fleets and autonomous systems operating in RF-denied or air-gapped environments
- Industrial IoT clusters in secure facilities
- Edge AI inference nodes in vehicles, spacecraft, and remote installations
- Any multi-node embedded system that needs post-quantum-ready cryptographic foundations

The market for secure embedded AI compute is growing. A standardized, open, lightweight entropy distribution protocol is infrastructure that does not currently exist.

---

## 3. Scope of Work

### 3.1 Required Deliverables

Proposals must address all of the following:

**D1 — EDP Protocol Specification**  
A complete protocol specification document suitable for IETF Internet-Draft submission. Must cover: packet formats, key management, entropy source classification, conditioning algorithm, mixing algorithm, security model, and failure modes. Should build on or reference the Hydrogenuine EDP v0.1-DRAFT (provided as Attachment A to this RFP).

**D2 — Reference Implementation**  
A production-quality C implementation of the EDP daemon targeting RISC-V (RV32IMC and RV64GC). Requirements:
- Builds with GCC RISC-V toolchain, no external runtime dependencies beyond libc
- Runs on Linux 5.x kernel (embedded config, musl libc acceptable)
- RAM footprint < 64 KB resident
- CPU overhead < 2% on RV32IMC E-class core at 200 MHz
- Integrates with Linux getrandom / kernel entropy pool
- Open source (MIT or Apache 2.0 license)

**D3 — FPGA TRNG Core**  
A synthesizable Verilog or VHDL ring-oscillator TRNG core targeting Lattice ECP5. Requirements:
- Passes NIST SP 800-90B IID entropy estimation tests
- Minimum 1 Mbit/s raw output rate
- Narrow memory-mapped FIFO interface to RISC-V host
- Synthesizable with open toolchain (Yosys + nextpnr)
- Open source (MIT, Apache 2.0, or CERN OHL)

**D4 — Test Suite**  
An automated test suite covering all test cases in EDP Specification Section 12. Must include:
- Unit tests for packet parsing, signature verification, entropy conditioning
- Integration tests for 3-node minimum mesh on physical hardware or QEMU
- Security tests including poisoning resistance and replay prevention
- Performance benchmarks with CSV output

**D5 — NIST SP 800-90B Entropy Estimation Report**  
For each claimed entropy source (FPGA TRNG, IMU, encoder jitter, timing jitter), provide a formal entropy estimation report using the NIST SP 800-90B methodology. This is the primary quality assurance document for source tier assignment.

**D6 — IETF Internet-Draft (optional but valued)**  
Submission of an individual Internet-Draft to the IETF ROLL (Routing Over Low-power and Lossy networks) working group or a new proposed working group. Hydrogenuine will support this submission but does not require it as a contract deliverable.

### 3.2 Out of Scope

The following are explicitly out of scope for this RFP:

- DOCS OCU hardware design (covered separately)
- Agent Zero orchestration software
- Android chassis design or actuation
- Post-quantum cryptographic algorithms (EDP uses Ed25519 and BLAKE3; PQ upgrade is a future RFP)
- Internet-connected deployment scenarios

---

## 4. Technical Requirements

### 4.1 Protocol Requirements (must meet)

| Requirement | Specification |
|---|---|
| Architecture | Peer-to-peer mesh; no designated entropy server |
| Transport | UDP multicast, 2.5GbE or equivalent Ethernet |
| Identity / authentication | Ed25519 per-node keypairs |
| Entropy conditioning | BLAKE3 keyed hash |
| Pool mixing | BLAKE3 chaining (external entropy additive only; never replaces pool) |
| Source tier classification | Minimum 4 tiers: FPGA TRNG, Hardware TRNG, Sensor Physical, Timing Jitter |
| Poisoning resistance | Proven: adversary controlling all remote nodes cannot reduce local pool entropy |
| Replay resistance | Monotonic sequence numbers per source node |
| Rate limiting | Max 2 EC packets/second accepted per remote node |
| PTP compatibility | Optional EPOCH_SYNC support; graceful degradation without PTP |
| Fault tolerance | Mesh continues entropy distribution if any single node fails |

### 4.2 Implementation Requirements (must meet)

| Requirement | Specification |
|---|---|
| Target ISA | RISC-V RV32IMC (E-class) and RV64GC (U-class) |
| OS | Linux 5.x, musl or glibc |
| RAM | < 64 KB RSS |
| Flash | < 128 KB binary |
| CPU | < 2% average, < 10% burst on 200 MHz E-core |
| Network | < 2 KB/s outbound per node |
| Startup time | EDP operational and broadcasting within 10s of boot |
| License | MIT or Apache 2.0 |
| Build system | CMake or Meson; cross-compilation supported |

### 4.3 FPGA TRNG Requirements (must meet)

| Requirement | Specification |
|---|---|
| Target | Lattice ECP5 (Yosys + nextpnr + Project Trellis) |
| Raw output rate | > 1 Mbit/s |
| Entropy estimate | > 0.5 bits/bit raw output (NIST SP 800-90B) |
| Interface | Memory-mapped FIFO, 32-bit words |
| Self-test | Built-in BIST with pass/fail status register |
| License | MIT, Apache 2.0, or CERN OHL-S/W/P |

### 4.4 Test Coverage Requirements

| Category | Minimum Coverage |
|---|---|
| Unit tests | 100% of public API functions |
| Integration tests | 3-node mesh, physical or emulated |
| Security tests | All 6 SEC-series tests from spec Section 12.3 |
| Performance tests | All 6 PERF-series tests from spec Section 12.5 |
| NIST SP 800-90B | For each claimed Tier 0, 1, and 2 source |

---

## 5. Evaluation Criteria

Proposals will be evaluated on the following criteria:

| Criterion | Weight |
|---|---|
| Technical approach and security model soundness | 35% |
| RISC-V implementation maturity and resource efficiency | 20% |
| FPGA TRNG quality and open toolchain compatibility | 15% |
| Test coverage and formal entropy estimation methodology | 15% |
| Team credentials (embedded security, cryptography, RISC-V) | 10% |
| Path to IETF standardization | 5% |

Proposals that claim full compliance but provide no supporting benchmarks, entropy estimates, or prototype evidence will be scored lower than proposals with partial compliance and solid empirical data.

---

## 6. Proposal Format

Proposals should include the following sections (suggested page limits):

1. **Executive Summary** (1 page): approach, key differentiators, prior work
2. **Technical Approach** (4–8 pages): protocol design decisions, security proof sketch, implementation architecture
3. **Entropy Source Analysis** (2–4 pages): which sources, estimated rates, conditioning method, tier justification
4. **FPGA TRNG Design** (2–3 pages): ring oscillator architecture, synthesis results on ECP5, BIST design
5. **Test Plan** (2–3 pages): how the test suite is structured, tooling, CI pipeline
6. **Team and Prior Work** (1–2 pages): relevant publications, open source contributions, hardware experience
7. **Timeline and Milestones** (1 page): phased delivery schedule
8. **Budget** (1 page): cost breakdown by deliverable
9. **Open Source Commitment** (0.5 page): explicit statement of license, repository hosting, long-term maintenance intent

---

## 7. Intellectual Property

All deliverables under this contract must be released as open source under MIT, Apache 2.0, or CERN OHL (for hardware). Hydrogenuine retains no exclusive rights. The goal is a public protocol that benefits the embedded AI and robotics community broadly.

Proposers may retain copyright over their implementation while granting open source license. Hydrogenuine will be listed as a co-author on any resulting IETF Internet-Draft.

Prior art and related work published by proposers before this RFP is unaffected by this requirement.

---

## 8. Attachments

- **Attachment A:** Hydrogenuine EDP Specification v0.1-DRAFT (`hydrogenuine_edp_spec.md`)
- **Attachment B:** Hydrogenuine DOCS Architecture Specification v0.1-DRAFT (`hydrogenuine_docs_spec.md`)
- **Attachment C:** Relevant prior art bibliography (see Section 9)

---

## 9. Prior Art Bibliography

Proposers should be familiar with the following:

- Paju et al., "External entropy supply for IoT devices employing a RISC-V Trusted Execution Environment," arXiv:2603.09311, March 2026
- Anonymous (redacted), "Post-Quantum Entropy as a Service for Embedded Systems," arXiv:2603.10274 / Sensors 26(9):2737, April 2026
- Kelsey et al., "Randomness Recommendations for Security," RFC 4086, IETF, June 2005
- Vasile et al., "Welcome to the Entropics: Boot-Time Entropy in Embedded Devices," IEEE S&P 2014
- Rogaway and Shrimpton, "Cryptographic Hash-Function Basics: Definitions, Implications, and Separations for Preimage Resistance, Second-Preimage Resistance, and Collision Resistance," 2004
- NIST SP 800-90B, "Recommendation for the Entropy Sources Used for Random Bit Generation," NIST, January 2018
- Syta et al. (drand team), "Scalable Bias-Resistant Distributed Randomness," IEEE S&P 2017
- Shannon, C.E., "A Mathematical Theory of Communication," Bell System Technical Journal, 1948

---

## 10. Questions and Clarifications

Questions regarding this RFP should be submitted in writing. Hydrogenuine will publish answers to all questions received, to maintain a level playing field.

Contact: Project DOCS Technical Lead  
Project: Hydrogenuine — github.com/hydrogenuine (placeholder)

---

*Hydrogenuine reserves the right to award to multiple proposers, award no contract, or issue a revised RFP. This is a research-stage project; proposers with partial solutions or early-stage implementations are encouraged to apply.*

---

*End of RFP HYD-RFP-2026-001*
