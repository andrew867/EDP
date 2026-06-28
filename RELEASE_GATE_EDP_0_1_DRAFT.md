# Release Gate: EDP 0.1-DRAFT

**Release:** EDP v0.1-DRAFT  
**Date:** 2026-06-28  
**Verdict:** See bottom of this document.

This checklist was completed before the initial public push to GitHub.
Each item is marked PASS, FAIL, or SKIP (with reason).

---

## Documentation

| Check | Status | Notes |
|-------|--------|-------|
| README.md exists | ✅ PASS | |
| README has status banner (not production-ready) | ✅ PASS | First visible content after title |
| README has "What EDP is not" section | ✅ PASS | |
| README has prior art table | ✅ PASS | |
| README has build instructions | ✅ PASS | |
| README has test instructions | ✅ PASS | |
| README has known limitations | ✅ PASS | Links to docs/protocol_limitations.md |
| README has port status note | ✅ PASS | Port 4086 marked unassigned/aspirational |
| LICENSE exists | ✅ PASS | MIT |
| NOTICE.md exists | ✅ PASS | BLAKE3 + Monocypher license notes |
| SECURITY.md exists | ✅ PASS | |
| CONTRIBUTING.md exists | ✅ PASS | |
| CHANGELOG.md exists | ✅ PASS | |
| docs/edp_spec.md exists | ✅ PASS | |
| docs/threat_model.md exists | ✅ PASS | |
| docs/protocol_limitations.md exists | ✅ PASS | |
| docs/prior_art.md exists | ✅ PASS | |

---

## Claims and language

| Check | Status | Notes |
|-------|--------|-------|
| No "production-ready" claim | ✅ PASS | |
| No "FIPS/NIST certified" claim | ✅ PASS | |
| No "independently audited" claim | ✅ PASS | Explicitly disclaimed |
| No "IANA-assigned" port claim | ✅ PASS | Port 4086 marked aspirational/unassigned |
| No "BLAKE3 is a bijection" claim | ✅ PASS | Fixed in edp_mix.c; uses "proof sketch / random-oracle model" |
| No "entropy can only increase" claim | ✅ PASS | Language: "should not reduce security of uncompromised local pool" |
| All proof sections say "proof sketch" | ✅ PASS | |
| FPGA TRNG marked as prototype | ✅ PASS | In Verilog files and README tier table |
| NIST SP 800-90B reports marked planned | ✅ PASS | Not present; documented as planned |
| No "military-grade" / "unbreakable" language | ✅ PASS | |
| All prior art claims cited | ✅ PASS | docs/prior_art.md, README prior art table |
| "Requires measurement" for sensor sources | ✅ PASS | README tier table + limitations doc |

---

## Code and build

| Check | Status | Notes |
|-------|--------|-------|
| CMakeLists.txt references no missing files | ✅ PASS | tests/bench.c stub added |
| bench target is buildable | ✅ PASS | Stub implementation; does nothing useful |
| Vendor dependencies documented | ✅ PASS | cmake/fetch_vendors.sh + NOTICE.md |
| Vendor files not committed | ✅ PASS | .gitignore excludes vendor/ |
| .gitignore exists | ✅ PASS | |
| No identity.bin committed | ✅ PASS | .gitignore excludes identity.bin |

---

## Build and test status

*Note: Build requires BLAKE3 and Monocypher from `cmake/fetch_vendors.sh`.*
*Results below are from a sandbox Linux environment.*

| Check | Status | Notes |
|-------|--------|-------|
| cmake configuration succeeds | PASS | CI run 28326683008 |
| cmake build succeeds | PASS | CI run 28326683008 |
| Unit tests pass (24/24) | PASS | CI run 28326683008 |
| Security tests pass (8/8) | PASS | CI run 28326683008 |
| Integration tests pass | SKIP | Multicast loopback unavailable on GitHub Actions |
| FPGA simulation (iverilog) passes | SKIP | iverilog not installed in CI |

**CI evidence:** https://github.com/andrew867/EDP/actions/runs/28326683008

---

## Security and secrets scan

| Check | Status | Notes |
|-------|--------|-------|
| No private paths (C:\, /home/andrew, etc.) | ✅ PASS | Scan found none |
| No credentials or API keys | ✅ PASS | |
| No tokens or private keys | ✅ PASS | |
| No unrelated Hydrogenuine AGI/governance content | ✅ PASS | EDP-specific content only |
| References to "Agent Zero" removed from source | ✅ PASS | Spec mention contextualized; no private detail |
| "private key" mentions are protocol-correct | ✅ PASS | All references are to Ed25519 protocol keys |

---

## What is safe to claim

- EDP is a draft peer-to-peer entropy augmentation protocol for embedded systems.
- Each node keeps its own local entropy pool and mixes authenticated remote contributions into it.
- Remote contributions should not reduce the security of an uncompromised local pool,
  under the random-oracle assumption for BLAKE3 (proof sketch only).
- The reference implementation runs on Linux x86 and cross-compiles to RISC-V (riscv64-musl).
- Prior art was surveyed in March-June 2026 and EDP's peer-mesh architecture
  appears to be novel as of that date.
- The BLAKE3 and Monocypher libraries have their own security histories; EDP uses them
  as dependencies, not as novel cryptographic contributions.

## What must not be claimed

- Production-ready.
- FIPS/NIST/formally certified.
- BLAKE3 is a bijection (say: BLAKE3 conditioning over secret pool state).
- Entropy can only increase (say: predictable input should not reduce security of uncompromised pool).
- Port 4086 is IANA-assigned.
- FPGA TRNG entropy output is validated.
- NIST SP 800-90B reports exist for any source.
- The implementation has been audited.
- EDP is an IETF standard.

---

## Final verdict

**READY TO PUSH: YES** -- public CI is green (unit 24/24, security 8/8),
and consumers must treat this as a research/prototype release per all
documentation.

The repository is honest about what it is and what it is not. That's the bar
for this release.
