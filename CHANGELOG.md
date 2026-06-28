# Changelog

All notable changes to EDP will be documented here.

## [0.1-DRAFT] -- 2026-06-28

Initial public research release. This is a protocol draft and reference
implementation. Nothing here should be considered stable or production-ready.

### Added

- EDP protocol specification v0.1 (`docs/edp_spec.md`)
- C reference daemon: entropy harvesting, pool mixing, peer mesh management
- FPGA TRNG prototype Verilog (ECP5 target, not silicon-validated)
- Ed25519-based node identity and packet signing via Monocypher
- BLAKE3-based entropy pool conditioning via BLAKE3 C reference
- Security mitigations: Sybil delay, replay protection, rate limiting, tier fraud detection
- Unit tests (22 cases), security property tests (8 cases), integration test skeleton
- CMake build system with RISC-V cross-compile support
- Threat model and known limitations documentation

### Known issues

- `tests/bench.c` is a stub; benchmark targets are not yet implemented.
- PTP EPOCH_SYNC uses local monotonic clock fallback, not true PTP sync.
- NIST SP 800-90B reports for all claimed entropy sources are planned but
  not yet conducted.
- Port 4086 is unassigned; use `--port` to override.
- FPGA TRNG output quality has not been independently measured.
