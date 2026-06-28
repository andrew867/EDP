/*
 * edp_crypto.c  -- Cryptographic primitives for EDP
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#include "edp_crypto.h"
#include <string.h>

/* Vendored BLAKE3 and Monocypher headers */
#include "../vendor/blake3.h"
#include "../vendor/monocypher.h"

/* ── BLAKE3 ────────────────────────────────────────────────────── */

void edp_blake3_hash(const uint8_t *in, size_t in_len, uint8_t out[32])
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, in, in_len);
    blake3_hasher_finalize(&h, out, 32);
}

void edp_blake3_keyed(const uint8_t key[32],
                      const uint8_t *in, size_t in_len,
                      uint8_t out[32])
{
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    blake3_hasher_update(&h, in, in_len);
    blake3_hasher_finalize(&h, out, 32);
}

void edp_blake3_chain(uint8_t state[32], const uint8_t *data, size_t len)
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, state, 32);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, state, 32); /* in-place update */
}

/* ── Ed25519 (Monocypher) ──────────────────────────────────────── */

void edp_ed25519_keygen(const uint8_t seed[32],
                        uint8_t pub[32],
                        uint8_t priv[64])
{
    crypto_eddsa_key_pair(priv, pub, seed);
}

void edp_ed25519_sign(const uint8_t priv[64],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t sig[64])
{
    crypto_eddsa_sign(sig, priv, msg, msg_len);
}

int edp_ed25519_verify(const uint8_t pub[32],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig[64])
{
    return crypto_eddsa_check(sig, pub, msg, msg_len); /* 0=ok, -1=fail */
}

/* ── Von Neumann corrector ─────────────────────────────────────── */

size_t edp_von_neumann(const uint8_t *in_bits, size_t in_bytes,
                       uint8_t *out, size_t out_max)
{
    size_t out_byte = 0;
    int    out_bit  = 0;
    uint8_t out_acc = 0;

    for (size_t i = 0; i < in_bytes && out_byte < out_max; i++) {
        uint8_t byte = in_bits[i];
        /* Process 4 pairs of bits per input byte */
        for (int pair = 0; pair < 4 && out_byte < out_max; pair++) {
            int b0 = (byte >> (pair * 2))     & 1;
            int b1 = (byte >> (pair * 2 + 1)) & 1;
            if (b0 != b1) {
                /* Non-equal pair: emit b0 */
                out_acc |= (uint8_t)(b0 << out_bit);
                out_bit++;
                if (out_bit == 8) {
                    out[out_byte++] = out_acc;
                    out_acc = 0;
                    out_bit = 0;
                }
            }
            /* Equal pairs (00 or 11) are discarded */
        }
    }
    /* Partial output byte is discarded (not emitted) to avoid bias */
    return out_byte;
}

/* ── Secure wipe ───────────────────────────────────────────────── */

void edp_wipe(void *buf, size_t len)
{
    /*
     * Monocypher provides crypto_wipe() which is explicitly not
     * optimized away by compilers.
     */
    crypto_wipe(buf, len);
}
