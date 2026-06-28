/*
 * edp_mix.c  -- Entropy pool management and mixing
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Core security property (sketch): for any fixed external input, BLAKE3 over the
 * secret pool state acts as a conditioned mixing step. Predictable remote input
 * should not reduce the security of an uncompromised local pool under the random-
 * oracle model. This is a proof sketch, not a formal verification.
 */
#include "edp_mix.h"
#include "edp_crypto.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#include <stdio.h>

/* ── Staging buffer ────────────────────────────────────────────── */

void edp_staging_init(edp_staging_t *s)
{
    memset(s, 0, sizeof(*s));
}

void edp_staging_push(edp_staging_t *s, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        s->data[s->head] = data[i];
        s->head = (s->head + 1) % EDP_STAGING_CAPACITY;
        if (s->used < EDP_STAGING_CAPACITY)
            s->used++;
    }
}

size_t edp_staging_drain(edp_staging_t *s, uint8_t *out, size_t want)
{
    size_t avail = s->used < want ? s->used : want;
    size_t tail  = (s->head - s->used + EDP_STAGING_CAPACITY) % EDP_STAGING_CAPACITY;

    for (size_t i = 0; i < avail; i++) {
        out[i] = s->data[(tail + i) % EDP_STAGING_CAPACITY];
    }
    s->used -= avail;
    return avail;
}

/* ── Pool ──────────────────────────────────────────────────────── */

void edp_pool_init(edp_pool_t *pool, const uint8_t *seed, size_t seed_len)
{
    memset(pool, 0, sizeof(*pool));
    if (seed && seed_len > 0) {
        /* Bootstrap pool state from seed */
        edp_blake3_hash(seed, seed_len, pool->state);
        pool->entropy_estimate = seed_len * 8 / 2; /* conservative: 0.5 bits/bit */
    } else {
        /* Derive initial state from getrandom */
        uint8_t bootstrap[32];
        getrandom(bootstrap, sizeof(bootstrap), 0);
        edp_blake3_hash(bootstrap, sizeof(bootstrap), pool->state);
        pool->entropy_estimate = 128; /* assume kernel has at least 128 bits */
        edp_wipe(bootstrap, sizeof(bootstrap));
    }
}

void edp_pool_mix_local(edp_pool_t *pool, const uint8_t *data, size_t len,
                         uint8_t source_tier)
{
    /*
     * Mix local harvest into pool.
     * state = BLAKE3(state || data || tier_byte)
     */
    uint8_t tier_byte = source_tier;
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pool->state, 32);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_update(&h, &tier_byte, 1);
    blake3_hasher_finalize(&h, pool->state, 32);

    pool->mix_count++;
    /* Conservative entropy accounting: credit at most 1 bit per 2 input bytes */
    uint64_t credit = (uint64_t)(len * 4); /* bits */
    /* Cap based on tier */
    uint64_t tier_cap[] = {8192, 4096, 512, 128, 0, 0};
    if (source_tier < 6 && credit > tier_cap[source_tier])
        credit = tier_cap[source_tier];
    pool->entropy_estimate += credit;
    if (pool->entropy_estimate > 256) pool->entropy_estimate = 256; /* cap at 256 bits */
}

void edp_pool_mix_remote(edp_pool_t *pool,
                          const uint8_t *ec_entropy, size_t ec_len,
                          const uint8_t *source_metadata, size_t meta_len,
                          uint8_t peer_tier)
{
    /*
     * Mix remote EC into pool.
     *
     * Security note: this function is called ONLY after the EC packet has
     * been verified (valid Ed25519 signature, valid sequence number, peer
     * in TRUSTED state, rate limit not exceeded).
     *
     * Even if ec_entropy is adversarially chosen (all zeros, all ones, etc.),
     * BLAKE3 conditioning over the secret pool state means predictable remote input
     * should not reduce the security of an uncompromised local pool (proof sketch;
     * not formally verified).
     */
    uint8_t remote_tag = 0xEE; /* distinguish remote from local in hash */
    uint8_t tier_byte  = peer_tier;

    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pool->state, 32);
    blake3_hasher_update(&h, &remote_tag, 1);
    blake3_hasher_update(&h, ec_entropy, ec_len);
    if (source_metadata && meta_len > 0)
        blake3_hasher_update(&h, source_metadata, meta_len);
    blake3_hasher_update(&h, &tier_byte, 1);
    blake3_hasher_finalize(&h, pool->state, 32);

    pool->mix_count++;
    /* Credit 0 for UNKNOWN tier; small credit for Tier 3+; real credit for Tier 0/1 */
    if (peer_tier <= EDP_TIER_SENSOR_PHYSICAL) {
        uint64_t credit = 32; /* 32 bits for physical sources */
        if (peer_tier == EDP_TIER_FPGA_TRNG) credit = 64;
        pool->entropy_estimate += credit;
        if (pool->entropy_estimate > 256) pool->entropy_estimate = 256;
    }
}

void edp_pool_extract(edp_pool_t *pool, uint8_t *out, size_t len)
{
    /*
     * Derive output bytes from pool using BLAKE3 XOF (extendable output).
     * After extraction, re-key the pool state to provide forward secrecy.
     */
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, pool->state, 32);
    blake3_hasher_finalize(&h, out, len);

    /* Re-key: derive new pool state from output + a counter */
    uint8_t rekey_input[36];
    memcpy(rekey_input, out, len < 32 ? len : 32);
    uint32_t rekey_ctr = (uint32_t)pool->mix_count;
    memcpy(rekey_input + 32, &rekey_ctr, 4);
    edp_blake3_hash(rekey_input, sizeof(rekey_input), pool->state);
    edp_wipe(rekey_input, sizeof(rekey_input));
}

void edp_pool_inject_to_kernel(edp_pool_t *pool,
                                void (*injector)(const uint8_t *, size_t))
{
    /*
     * Extract 64 bytes from pool and feed to kernel entropy pool.
     * Called after each successful remote mix and on HARVEST_INTERVAL.
     */
    uint8_t out[64];
    edp_pool_extract(pool, out, sizeof(out));

    if (injector) {
        injector(out, sizeof(out));
    } else {
        /* Fallback: write to /dev/urandom */
        int fd = open("/dev/urandom", O_WRONLY);
        if (fd >= 0) {
            write(fd, out, sizeof(out));
            close(fd);
        }
    }
    edp_wipe(out, sizeof(out));
}
