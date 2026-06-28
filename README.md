# EDP: Entropy Distribution Protocol

![CI](https://github.com/andrew867/EDP/actions/workflows/ci.yml/badge.svg)

> **Status: 0.1-DRAFT / research prototype / not production crypto**

EDP is a draft peer-to-peer entropy augmentation protocol for embedded systems --
anywhere a fleet of constrained devices boots from the same power event and needs
cryptographic randomness before local entropy has accumulated. No central server.
No call-home. Every node contributes, every contribution is Ed25519-signed, and
the protocol is designed so that a compromised peer cannot degrade a healthy
neighbor's entropy pool.

Target: RISC-V embedded (Kendryte K230-class), but the reference implementation
builds on any POSIX system with a C11 compiler.

This repository is the protocol specification and a reference C implementation.
Neither is production-ready. Neither has been independently audited. Treat this as
a research starting point.

---

## What EDP is

- A peer-to-peer UDP multicast protocol where every node can produce and consume entropy.
- An augmentation layer, not a replacement for local hardware TRNGs or the OS CSPRNG.
- Designed for constrained RISC-V embedded systems (Kendryte K230-class, ~200MHz, <64KB RAM).
- Authenticated: each node has an Ed25519 identity keypair. Unsigned contributions are rejected.
- Designed to resist entropy-pool poisoning: a peer contribution is mixed with
  the local secret pool state and never replaces it.

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
be thin. When you have a mesh of such devices -- robot limbs, sensor nodes, edge
compute units -- they all have this problem at the same time, from the same power-on
event.

EDP lets them pool what they have. Each node mixes contributions from its peers into
its local state. If one node has a good hardware TRNG, its neighbors benefit. If a
node is compromised or sends junk, the construction is intended to ensure
that healthy neighbors are not made worse off.

The closed-loop aspect is the novel part. All prior work we found uses a client-server
model (one trusted entropy server, many clients). EDP has no server. Every node is a
peer.

---

## Prior art

| Reference | Approach | Gap |
|-----------|----------|-----|
| arXiv:2603.09311 | IoT entropy via RISC-V TEE server | Client-server only |
| arXiv:2603.10274 / QEaaS | QRNG to ESP32 clients over PQC channels | Expensive QRNG hardware required |
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
                    +-------------------------------------+
                    |          EDP Mesh (UDP multicast)   |
                    |        224.0.86.1 : 4086 (draft)    |
                    +-------------------------------------+
                           |              |              |
              +------------+    +---------+    +---------+
              |                 |              |
         +----v----+       +----v----+    +----v----+
         |  OCU-A  |       |  OCU-B  |    |  OCU-C  |
         | (arm L) |       | (torso) |    | (arm R) |
         +---------+       +---------+    +---------+
         | FPGA    |       | HW TRNG |    | IMU src |
         | TRNG    |       | Seed CSR|    | jitter  |
         +---------+       +---------+    +---------+
         | edp_pool|<------| edp_pool|--->| edp_pool|
         | state   | mix   | state   |mix | state   |
         +---------+       +---------+    +---------+

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
| 0 | FPGA ring-oscillator TRNG | >1 Mbit/s | Prototype -- needs measurement |
| 1 | RISC-V `seed` CSR (Zkt extension) | ~1 Mbit/s | Hardware-attested; K230 specific |
| 2 | Sensor physical noise (IMU, encoder, CAN FD) | ~1-2 Kbit/s est. | Requires NIST SP 800-90B assessment |
| 3 | HAVEGE timing jitter | Variable | Software-only; weakest tier |

All rates are design estimates. None have been formally measured. Do not use tier
assignments as security guarantees without independent entropy measurement.

---

## Potential application: gaming and lottery systems

Casino floors are meshes of embedded machines that all power on at the same time.

A typical slot machine or video lottery terminal (VLT) runs a constrained embedded
OS on hardware that has been in service for years -- sometimes decades. At boot,
before enough hardware events have accumulated, the local entropy pool is thin.
Every machine on the floor hits this window simultaneously, from the same breaker
panel, after the same power cycle. The result is a fleet of devices making
security-critical random draws from shallow pools during exactly the period when
the floor is opening and players are arriving.

This is the same mesh-of-constrained-devices problem EDP was designed for.

**Where EDP fits in the gaming stack:**

- **Slot machines and VLTs.** Legacy gaming hardware often lacks a dedicated TRNG.
  EDP lets machines on the same floor segment augment each other's entropy pools
  over the existing network fabric, without replacing the certified per-machine RNG.
  The protocol rides alongside G2S (Game to System) or SAS -- it does not modify
  game outcome logic.

- **Linked progressive jackpots.** Progressive systems span dozens or hundreds of
  machines across multiple properties. The central controller that triggers a
  jackpot event needs high-quality randomness that is not correlated with any
  single machine's local state. A mesh of EDP peers feeding the controller means
  no single point of entropy failure.

- **Instant-win and point-of-sale games.** Lottery terminals at retail counters,
  promotional kiosks, and contest-draw systems are embedded devices in the same
  class as VLTs -- low-power, long-lived, booting from flash with minimal
  entropy sources. They often run draws within seconds of power-on.

- **Backend servers.** Promotional game engines, contest platforms, and lottery
  draw servers can use EDP as a peer entropy feed alongside their existing
  CSPRNG, adding diversity without single-source dependence.

- **Regulatory fit.** Gaming jurisdictions require certified RNGs (GLI-19,
  BMM testlabs, provincial/state gaming commissions). EDP is an entropy
  *source layer*, not an RNG replacement. It feeds the pool that the certified
  RNG draws from. The per-contribution Ed25519 signatures provide an audit
  trail that regulators can inspect: which peer contributed what, when, and
  whether the signature verified.

**Important caveats:** EDP is a draft protocol and is not certified for
regulated gaming use. Any deployment in a gaming environment would require
independent certification by an accredited testing laboratory. The use case
described here is a potential application, not a claim of readiness.

---

## Potential application: autonomous fleets and edge AI

Any fleet of devices that boots together has an entropy problem.

A thousand autonomous vehicles receive the same OTA update overnight. At 6 AM,
they all cold-start from the same firmware image, on the same silicon, within
the same few minutes. Each one needs cryptographic randomness immediately --
TLS session keys for fleet telemetry, nonces for sensor-fusion authentication,
sampling entropy for on-device inference. The hardware TRNG (if one exists)
may not have accumulated enough thermal noise yet. The OS entropy pool is
near-empty. And every vehicle in the lot is in the same state at the same time.

EDP turns that fleet into a mesh. Each vehicle contributes what entropy it has.
One vehicle's wheel-speed jitter is another vehicle's remote entropy source.
The protocol never replaces local entropy -- it augments it. A compromised node
in the fleet cannot poison its neighbors' pools. And because EDP is peer-to-peer,
the fleet does not depend on reaching a cloud entropy service to bootstrap.

**Where this applies:**

- **Autonomous vehicle fleets.** Cars, trucks, delivery robots, drones -- any
  fleet that OTA-updates and cold-starts together. EDP provides entropy
  diversity from the physical mesh without requiring internet connectivity
  at boot. The Ed25519 audit trail lets fleet operators verify which peer
  contributed what entropy and when.

- **On-device AI inference.** Local language models, vision models, and
  decision systems need randomness for token sampling, differential privacy
  noise, and exploration in reinforcement learning. When inference runs on
  the device (not in the cloud), local entropy quality matters. A mesh of
  peer devices pooling entropy means no single device is stuck with only
  its own boot-time randomness.

- **RISC-V robotics.** The reference implementation targets Kendryte K230-class
  RISC-V SoCs -- the same class of silicon shipping in current-generation
  embedded robotics and edge compute platforms. A robot's limbs, torso, and
  sensor arrays are separate embedded nodes on the same bus. EDP lets them
  share entropy across that bus without trusting any single limb's local source.

- **Mesh-connected IoT at scale.** Smart grid sensors, industrial controllers,
  agricultural monitoring nodes -- any deployment where hundreds or thousands
  of embedded devices share a local network and boot from the same firmware.
  EDP requires only UDP multicast and ~4KB of RAM per peer.

- **Air-gapped and denied environments.** Because EDP is peer-to-peer with no
  cloud dependency, it works in environments where calling home is not an
  option: submarine vehicles, underground mining, disaster-response mesh
  networks, or any deployment where connectivity is intermittent or
  deliberately severed.

**Important caveats:** EDP is a draft protocol. It has not been deployed in any
autonomous vehicle, robotics fleet, or production AI system. The applications
described here are potential use cases based on the protocol's design properties,
not claims of deployment or readiness. Any safety-critical use would require
independent security review and domain-specific certification.

---

## Building

### Prerequisites

- CMake >= 3.16
- GCC or Clang (C11)
- Vendored dependencies: BLAKE3 1.5.4, Monocypher 4.0.2

### Get vendored dependencies

```sh
./cmake/fetch_vendors.sh
```

This downloads `blake3.{c,h}`, `blake3_portable.c`, `blake3_dispatch.c`,
`blake3_impl.h`, `monocypher.{c,h}` into `vendor/`. They are not included
in the repo.

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
- **unit** -- 24 unit tests (BLAKE3, Ed25519, pool mixing, peer logic, staging buffer)
- **security** -- 8 security property tests (poisoning resistance, Sybil delay, rate
  limiting, forward secrecy, tier fraud detection)
- **integration** -- 3-node loopback mesh test (Linux only, requires `ip` and multicast
  route on loopback)

If vendor fetch is unavailable, the build may not complete. Document this
honestly; don't claim tests pass if you haven't run them.

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

MIT -- see [LICENSE](LICENSE).

Vendored dependencies (BLAKE3, Monocypher) have their own licenses; see [NOTICE.md](NOTICE.md).

---

## References

- RFC 4086 -- Eastlake et al., "Randomness Requirements for Security," IETF, 2005
- NIST SP 800-90B -- Turan et al., "Entropy Sources for Random Bit Generation," 2018
- arXiv:2603.09311 -- RISC-V TEE entropy supply for IoT
- arXiv:2603.10274 -- QEaaS: QRNG entropy distribution over PQC channels
- ACM 10.1145/3799895 -- Remote QRNG via D-Bus
- BLAKE3: https://github.com/BLAKE3-team/BLAKE3
- Monocypher: https://monocypher.org
