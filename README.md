# EDP — Entropy Distribution Protocol

> **Status: 0.1-DRAFT / research prototype / not production crypto**

EDP is a draft peer-to-peer entropy augmentation protocol for embedded systems.
Each node keeps its own local entropy pool. Remote contributions are authenticated,
conditioned, and mixed into that pool — they never replace local entropy. The goal
is to make a mesh of constrained devices less dependent on any single entropy service,
while keeping the failure mode boring: a bad peer can fail to help, but shouldn't
be able to make a healthy local pool worse.

This repository is the protocol specification and a reference C implementation.
Neither is production-ready. Neither has been independently audited. Treat this as
a research starting point.

---

## What EDP is

- A peer-to-peer UDP multicast protocol where every node can produce and consume entropy.
- An augmentation layer, not a replacement for local hardware TRNGs or the OS CSPRNG.
- Designed for constrained RISC-V embedded systems (Kendryte K230-class, ~200MHz, <64KB RAM).
- Authenticated: each node has an Ed25519 identity keypair. Unsigned contributions are rejected.
- Poisoning-resistant by construction: even an adversary controlling a peer's contribution
  input cannot predict the local pool output without knowing the local pool state.

## What EDP is not

- Not production-ready.
- Not FIPS/NIST certified.
- Not independently audited.
- Not IETF standardized (an IETF submission is aspirational).
- Not an IANA-assigned protocol (port 4086 is unassigned; see [Port status](#port-status)).
- Not a replacement for a local hardware TRNG or the Linux kernel CSPRNG.
- Not a guarantee that sensor readings contain usable entropy without independent measurement.

---

## Why this exists

Embedded systems with no hardware TRNG are common. During early boot, before the
network is up and before enough events have accumulated, the local entropy pool can
be thin. When you have a mesh of such devices — robot limbs, sensor nodes, edge
compute units — they all have this problem at the same time, from the same power-on
event.

EDP lets them pool what they have. Each node mixes contributions from its peers into
its local state. If one node has a good hardware TRNG, its neighbors benefit. If a
node is compromised or sends junk, the math says the healthy neighbors shouldn't be
made worse off.

The closed-loop aspect is the novel part. All prior work we found uses a client-server
model (one trusted entropy server, many clients). EDP has no server. Every node is a
peer.

---

## Prior art

| Reference | Approach | Gap |
|-----------|----------|-----|
| arXiv:2603.09311 | IoT entropy via RISC-V TEE server | Client-server only |
| arXiv:2603.10274 / QEaaS | QRNG → ESP32 clients over PQC channels | Expensive QRNG hardware required |
| ACM 10.1145/3799895 | Remote QRNG via D-Bus | Single host, not networked |
| drand | Distributed randomness beacon (BLS threshold sigs) | Internet-scale infrastructure, not embedded |
| Linux `/dev/random` | Kernel entropy pool from hardware events | Single-host; EDP complements, not replaces |

See [`docs/prior_art.md`](docs/prior_art.md) for full citations and discussion.

---

## Core security intuition

The pool update rule for a remote contribution is:

```
pool_{t+1} = BLAKE3(pool_t || remote_tag || ec_entropy || metadata || tier_byte)
```

The local pool state `pool_t` is secret. Under the random-oracle model, fixing
`ec_entropy` to any value (including adversarially chosen) doesn't allow predicting
or controlling `pool_{t+1}` without knowing `pool_t`. So external contributions
are mixed into local state without replacing it.

This is a proof sketch, not a formal proof. It relies on the random-oracle assumption
for BLAKE3. The actual security depends on the local pool being and remaining secret,
which requires the local platform to be uncompromised.

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           EDP Mesh (UDP multicast)  │
                    │         224.0.86.1 : 4086 (draft)   │
                    └─────────────────────────────────────┘
                           │              │              │
              ┌────────────┘    ┌─────────┘    ┌────────┘
              │                 │              │
         ┌────▼────┐       ┌────▼────┐    ┌───▼─────┐
         │  OCU-A  │       │  OCU-B  │    │  OCU-C  │
         │ (arm L) │       │ (torso) │    │ (arm R) │
         ├─────────┤       ├─────────┤    ├─────────┤
         │ FPGA    │       │ HW TRNG │    │ IMU src │
         │  TRNG   │       │ Seed CSR│    │ jitter  │
         ├─────────┤       ├─────────┤    ├─────────┤
         │ edp_pool│◄──────│ edp_pool│───►│edp_pool │
         │  state  │  mix  │  state  │mix │  state  │
         └─────────┘       └─────────┘    └─────────┘

Each node:
  1. Harvests local entropy from tiered sources (FPGA TRNG, Seed CSR, IMU, jitter).
  2. Conditions it through Von Neumann corrector + BLAKE3 keyed hash.
  3. Accumulates in local staging buffer.
  4. Broadcasts signed EC (Entropy Contribution) packets every ~1 second.
  5. Receives peers' EC packets, verifies Ed25519 signature, mixes into local pool.
  6. Optionally injects output from local pool into the kernel entropy interface.
```

### Candidate entropy source tiers

| Tier | Source | Claimed rate (unverified) | Notes |
|------|--------|--------------------------|-------|
| 0 | FPGA ring-oscillator TRNG | >1 Mbit/s | Prototype — needs measurement |
| 1 | RISC-V `seed` CSR (Zkt extension) | ~1 Mbit/s | Hardware-attested; K230 specific |
| 2 | Sensor physical noise (IMU, encoder, CAN FD) | ~1–2 Kbit/s est. | Requires NIST SP 800-90B assessment |
| 3 | HAVEGE timing jitter | Variable | Software-only; weakest tier |

All rates are design estimates. None have been formally measured. Do not use tier
assignments as security guarantees without independent entropy measurement.

---

## Building

### Prerequisites

- CMake ≥ 3.16
- GCC or Clang (C11)
- Vendored dependencies: BLAKE3 1.5.4, Monocypher 4.0.2

### Get vendored dependencies

```sh
./cmake/fetch_vendors.sh
```

This downloads `blake3.{c,h}`, `blake3_portable.c`, `blake3_impl.h`,
`monocypher.{c,h}` into `vendor/`. They are not included in the repo.

### Native build (x86, for testing)

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### RISC-V cross-compile

```sh
cmake -B build-riscv \
  -DCMAKE_TOOLCHAIN_FILE=cmake/riscv64-linux-musl.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-riscv
```

You need `riscv64-linux-musl-gcc` and a sysroot at `/opt/riscv64-musl`. Adjust
the toolchain file as needed.

---

## Testing

```sh
ctest --test-dir build -V
```

This runs:
- **unit** — 22 unit tests (BLAKE3 KATs, pool mixing, peer logic, staging buffer)
- **security** — 8 security property tests (poisoning resistance, Sybil delay, rate
  limiting, forward secrecy, tier fraud detection)
- **integration** — 3-node loopback mesh test (Linux only, requires `ip` and multicast
  route on loopback)

If vendor fetch is unavailable (no internet), integration tests will not build.
Document this honestly; don't claim tests pass if you haven't run them.

---

## Port status

Port 4086 is **not IANA-assigned**. IANA lists 4086/tcp as Reserved. EDP uses
4086 as an experimental default as a nod to RFC 4086 ("Randomness Requirements
for Security"). Use `--port` on the command line or the `EDP_PORT` environment
variable to override.

If EDP reaches IETF standardization, a port assignment will be sought at that time.

---

## Known limitations

See [`docs/protocol_limitations.md`](docs/protocol_limitations.md) for the full list.
Key issues:

- FPGA TRNG is a prototype; no silicon validation or NIST 800-90B report yet.
- PTP EPOCH_SYNC uses monotonic clock fallback, not real PTP.
- Benchmark stub only; no measured performance numbers.
- Sybil delay (30s) is a speed bump, not a strong defence.
- No formal entropy accounting; `entropy_estimate` is a heuristic.

---

## License

MIT — see [LICENSE](LICENSE).

Vendored dependencies (BLAKE3, Monocypher) have their own licenses; see [NOTICE.md](NOTICE.md).

---

## References

- RFC 4086 — Eastlake et al., "Randomness Requirements for Security," IETF, 2005
- NIST SP 800-90B — Turan et al., "Entropy Sources for Random Bit Generation," 2018
- arXiv:2603.09311 — RISC-V TEE entropy supply for IoT
- arXiv:2603.10274 — QEaaS: QRNG entropy distribution over PQC channels
- ACM 10.1145/3799895 — Remote QRNG via D-Bus
- BLAKE3: https://github.com/BLAKE3-team/BLAKE3
- Monocypher: https://monocypher.org
