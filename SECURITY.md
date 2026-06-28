# Security Policy

## Status

EDP is a **research/prototype implementation** (v0.1-DRAFT). It has not been
independently audited, formally verified, or certified. Do not deploy it in
production systems without a thorough security review.

Specifically:

- The FPGA TRNG design has not been silicon-validated or NIST SP 800-90B assessed.
- The entropy pool mixing relies on BLAKE3 under the random-oracle assumption.
  The security argument is a proof sketch, not a formal cryptographic proof.
- Actual entropy from IMU and timing sources depends on physical conditions and
  requires independent measurement before any tier assignment is meaningful.
- Port 4086 is not IANA-assigned and is used as an experimental default only.

## What EDP protects against (per threat model)

When the local pool is uncompromised and local entropy sources are healthy:

- A remote peer sending predictable or adversarial entropy contributions
  should not reduce the security of the local pool.
- Replay, spoofing, rate-flooding, and Sybil attacks are mitigated by the
  protocol mechanisms described in `docs/threat_model.md`.

## What EDP does not protect against

- Compromise of the local hardware platform.
- Systematic bias in all local entropy sources simultaneously.
- An attacker who can observe the full pool state.
- Side-channel attacks against the BLAKE3 or Ed25519 implementations.
- Denial-of-service against the UDP multicast transport.

See `docs/protocol_limitations.md` for a full limitations list.

## Reporting vulnerabilities

Please report security issues privately by emailing the maintainers directly
rather than opening a public GitHub issue. We will acknowledge within 5
business days and aim to publish a fix or advisory within 90 days.

There is currently no CVE process or bug bounty for this project given its
early research status.
