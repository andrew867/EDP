# Third-Party Notices

EDP depends on the following vendored libraries. They are not included in this
repository; run `./cmake/fetch_vendors.sh` to download them into `vendor/`.

---

## BLAKE3

- **Version:** 1.5.4
- **Source:** https://github.com/BLAKE3-team/BLAKE3/tree/1.5.4/c
- **License:** CC0-1.0 / Apache-2.0 (dual-licensed; see BLAKE3 repo)
- **Files fetched:** `vendor/blake3.h`, `vendor/blake3.c`,
  `vendor/blake3_portable.c`, `vendor/blake3_dispatch.c`, `vendor/blake3_impl.h`

> The BLAKE3 team has released the C reference implementation under CC0 and
> Apache-2.0. You may use it under either license. We use the portable C
> implementation only; no platform-specific assembly is fetched.

---

## Monocypher

- **Version:** 4.0.2
- **Source:** https://github.com/LoupVaillant/Monocypher/tree/4.0.2/src
- **License:** BSD-2-Clause (see Monocypher repo)
- **Files fetched:** `vendor/monocypher.h`, `vendor/monocypher.c`

> Monocypher is a small, audited cryptography library. EDP uses it for
> Ed25519 key generation, signing, and verification only.

---

No other third-party code is included. The EDP protocol specification and
reference implementation are original work released under the MIT License.
