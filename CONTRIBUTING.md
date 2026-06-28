# Contributing to EDP

EDP is an early research project. Contributions, critiques, and measurements are
welcome, especially anything that improves the honesty or accuracy of the security
claims.

## Before you contribute

Read `docs/protocol_limitations.md` and `SECURITY.md`. The biggest open questions
are about whether claimed entropy sources actually produce usable entropy in practice.
If you can measure this, that's the most valuable thing you could contribute right now.

## Ways to help

**Measurement:** Run the FPGA TRNG on real hardware and share NIST SP 800-90B
results. Same for IMU/encoder/CAN timing sources. We need data, not models.

**Protocol review:** Read `docs/edp_spec.md` and look for protocol-level issues —
especially around the Sybil delay, rate limiting, and the peer trust model.

**Code review:** The C daemon is a prototype. Review `src/edp_peer.c` and
`src/edp_mix.c` for correctness. The security properties are only as good as
the implementation.

**Build/portability:** Test on RISC-V hardware. Report what breaks.

**Documentation:** Fix wrong claims. Weaken overclaims. Add missing caveats.
This is more valuable than adding new features right now.

## What we're not looking for

- New entropy sources without entropy measurement data.
- Protocol extensions before the base protocol is stable.
- Performance optimizations before correctness is confirmed.

## How to submit

Open a GitHub issue to discuss before a large PR. Small fixes (typos, wrong
claims, build errors) can go directly as PRs.

Keep PRs focused. One change per PR makes review faster.

## Code style

C11. `clang-format` with the style in `.clang-format` (if present) or match the
surrounding code. No dynamic allocation in the daemon. No external dependencies
beyond BLAKE3 and Monocypher.

## License

By contributing, you agree your contributions are licensed under the MIT License.
