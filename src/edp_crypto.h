/*
 * edp_crypto.h  -- Cryptographic primitives for EDP
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Wraps BLAKE3 (CC0/Apache-2.0) and Monocypher Ed25519 (BSD-2-Clause).
 * No dynamic allocation. All buffers caller-provided.
 *
 * Dependencies (vendored in edp/vendor/):
 *   blake3.h + blake3.c   -- https://github.com/BLAKE3-team/BLAKE3
 *   monocypher.h + .c     -- https://monocypher.org
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* ── BLAKE3 wrappers ───────────────────────────────────────────── */

/*
 * edp_blake3_hash()  -- simple hash, output 32 bytes.
 */
void edp_blake3_hash(const uint8_t *in, size_t in_len, uint8_t out[32]);

/*
 * edp_blake3_keyed()  -- keyed hash for entropy conditioning.
 * key must be exactly 32 bytes.
 */
void edp_blake3_keyed(const uint8_t key[32],
                      const uint8_t *in, size_t in_len,
                      uint8_t out[32]);

/*
 * edp_blake3_chain()  -- update a running 32-byte state by chaining new input.
 * state = BLAKE3(state || data).
 * Used for pool mixing and staging buffer accumulation.
 */
void edp_blake3_chain(uint8_t state[32], const uint8_t *data, size_t len);

/* ── Ed25519 wrappers (Monocypher) ─────────────────────────────── */

/*
 * edp_ed25519_keygen()  -- derive public key from private key seed.
 * seed: 32 bytes of random data (from getrandom or TRNG).
 * pub: 32-byte output public key.
 * priv: 64-byte output private key (seed || pubkey).
 */
void edp_ed25519_keygen(const uint8_t seed[32],
                        uint8_t pub[32],
                        uint8_t priv[64]);

/*
 * edp_ed25519_sign()  -- sign msg with private key.
 * sig: 64-byte output signature.
 */
void edp_ed25519_sign(const uint8_t priv[64],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t sig[64]);

/*
 * edp_ed25519_verify()  -- verify signature.
 * Returns 0 on success (valid), -1 on failure.
 */
int edp_ed25519_verify(const uint8_t pub[32],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig[64]);

/* ── Von Neumann corrector ─────────────────────────────────────── */

/*
 * edp_von_neumann()  -- bit-level decorrelation.
 * Reads pairs of bits from in_bits (bit-packed); emits one output bit
 * per non-equal pair (00 or 11 pairs are discarded).
 * Returns number of bytes written to out (may be less than out_max).
 * in_bits: raw bit stream, in_bytes bytes long.
 * Typical efficiency: ~50% of input bits become output bits.
 */
size_t edp_von_neumann(const uint8_t *in_bits, size_t in_bytes,
                       uint8_t *out, size_t out_max);

/* ── Secure memory ─────────────────────────────────────────────── */

/*
 * edp_wipe()  -- zero memory in a way compilers won't optimize out.
 */
void edp_wipe(void *buf, size_t len);
