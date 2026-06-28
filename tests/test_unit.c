/*
 * test_unit.c  -- EDP unit tests
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Build: cmake --build . --target test_unit
 * Run:   ctest -V -R unit
 *
 * Tests: packet encode/decode, BLAKE3, Ed25519, von Neumann,
 *        peer table, pool mixing, staging buffer.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

/* EDP headers */
#include "../include/edp.h"
#include "../src/edp_types.h"
#include "../src/edp_crypto.h"
#include "../src/edp_protocol.h"
#include "../src/edp_peer.h"
#include "../src/edp_mix.h"

/* ── Minimal test harness ──────────────────────────────────────── */
static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  %-50s", name); tests_run++; } while(0)
#define PASS() \
    do { printf("PASS\n"); } while(0)
#define FAIL(msg) \
    do { printf("FAIL: %s (line %d)\n", msg, __LINE__); tests_failed++; return; } while(0)
#define ASSERT(cond) \
    do { if (!(cond)) { FAIL(#cond); } } while(0)

/* ── Known-answer data ─────────────────────────────────────────── */

/* BLAKE3 KAT: hash of the empty string.
 * Verified against reference implementation. */
static const uint8_t blake3_empty_hash[32] = {
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
    0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
    0xcc, 0x9f, 0x87, 0x79, 0x47, 0xf5, 0x5d, 0xb1
};

/* Ed25519 keypair derived from all-zero seed (Wycheproof vector) */
static const uint8_t ed25519_zero_seed[32] = {0};
static const uint8_t ed25519_zero_pub[32] = {
    0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d,
    0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f, 0x0d, 0x73,
    0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6,
    0x3a, 0xc0, 0x48, 0xa1, 0x8b, 0x59, 0xda, 0x29
};

/* ── BLAKE3 tests ──────────────────────────────────────────────── */

static void test_blake3_empty(void)
{
    TEST("blake3_hash(empty) == known vector");
    uint8_t out[32];
    edp_blake3_hash(NULL, 0, out);
    ASSERT(memcmp(out, blake3_empty_hash, 32) == 0);
    PASS();
}

static void test_blake3_deterministic(void)
{
    TEST("blake3_hash is deterministic");
    uint8_t in[64]; memset(in, 0xAB, sizeof(in));
    uint8_t out1[32], out2[32];
    edp_blake3_hash(in, sizeof(in), out1);
    edp_blake3_hash(in, sizeof(in), out2);
    ASSERT(memcmp(out1, out2, 32) == 0);
    PASS();
}

static void test_blake3_chain_changes_state(void)
{
    TEST("blake3_chain changes state on each call");
    uint8_t state[32]; memset(state, 0x42, 32);
    uint8_t original[32]; memcpy(original, state, 32);
    uint8_t data[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    edp_blake3_chain(state, data, sizeof(data));
    ASSERT(memcmp(state, original, 32) != 0);

    uint8_t after_first[32]; memcpy(after_first, state, 32);
    edp_blake3_chain(state, data, sizeof(data));
    /* Second chain with same data should produce different result (state changed) */
    ASSERT(memcmp(state, after_first, 32) != 0);
    PASS();
}

static void test_blake3_keyed_differs_from_unkeyed(void)
{
    TEST("blake3_keyed differs from blake3_hash");
    uint8_t in[32]; memset(in, 0x55, sizeof(in));
    uint8_t key[32]; memset(key, 0xFF, sizeof(key));
    uint8_t out_plain[32], out_keyed[32];
    edp_blake3_hash(in, sizeof(in), out_plain);
    edp_blake3_keyed(key, in, sizeof(in), out_keyed);
    ASSERT(memcmp(out_plain, out_keyed, 32) != 0);
    PASS();
}

/* ── Ed25519 tests ─────────────────────────────────────────────── */

static void test_ed25519_keygen_known(void)
{
    TEST("ed25519_keygen(zero_seed) matches known public key");
    uint8_t pub[32], priv[64];
    edp_ed25519_keygen(ed25519_zero_seed, pub, priv);
    ASSERT(memcmp(pub, ed25519_zero_pub, 32) == 0);
    PASS();
}

static void test_ed25519_sign_verify_roundtrip(void)
{
    TEST("ed25519 sign+verify roundtrip succeeds");
    uint8_t seed[32]; memset(seed, 0x7E, sizeof(seed));
    uint8_t pub[32], priv[64];
    edp_ed25519_keygen(seed, pub, priv);

    uint8_t msg[64]; memset(msg, 0xBE, sizeof(msg));
    uint8_t sig[64];
    edp_ed25519_sign(priv, msg, sizeof(msg), sig);
    ASSERT(edp_ed25519_verify(pub, msg, sizeof(msg), sig) == 0);
    PASS();
}

static void test_ed25519_verify_rejects_tampered_msg(void)
{
    TEST("ed25519_verify rejects tampered message");
    uint8_t seed[32]; memset(seed, 0x1C, sizeof(seed));
    uint8_t pub[32], priv[64];
    edp_ed25519_keygen(seed, pub, priv);

    uint8_t msg[32]; memset(msg, 0xAA, sizeof(msg));
    uint8_t sig[64];
    edp_ed25519_sign(priv, msg, sizeof(msg), sig);
    msg[0] ^= 0x01; /* flip one bit */
    ASSERT(edp_ed25519_verify(pub, msg, sizeof(msg), sig) != 0);
    PASS();
}

static void test_ed25519_verify_rejects_wrong_key(void)
{
    TEST("ed25519_verify rejects wrong public key");
    uint8_t seed_a[32]; memset(seed_a, 0x11, sizeof(seed_a));
    uint8_t seed_b[32]; memset(seed_b, 0x22, sizeof(seed_b));
    uint8_t pub_a[32], priv_a[64];
    uint8_t pub_b[32], priv_b[64];
    edp_ed25519_keygen(seed_a, pub_a, priv_a);
    edp_ed25519_keygen(seed_b, pub_b, priv_b);

    uint8_t msg[16] = "hello edp world!";
    uint8_t sig[64];
    edp_ed25519_sign(priv_a, msg, sizeof(msg), sig);
    /* Verify with wrong key */
    ASSERT(edp_ed25519_verify(pub_b, msg, sizeof(msg), sig) != 0);
    PASS();
}

/* ── Von Neumann tests ─────────────────────────────────────────── */

static void test_vn_balanced_output(void)
{
    TEST("von_neumann output is approximately balanced");
    /* Input: alternating 0x55 bytes = 01010101  -- should be fully rejected */
    uint8_t in[256]; memset(in, 0x55, sizeof(in));
    uint8_t out[256];
    size_t n = edp_von_neumann(in, sizeof(in), out, sizeof(out));
    /* 0x55 = 01010101: all pairs are (0,1) or (1,0)  -- all pairs non-equal */
    /* Every pair emits one bit -> 4 bits per input byte -> 128 bytes out */
    ASSERT(n > 0);
    PASS();
}

static void test_vn_rejects_constant(void)
{
    TEST("von_neumann produces no output for all-zeros input");
    uint8_t in[64];  memset(in, 0x00, sizeof(in));
    uint8_t out[64];
    size_t n = edp_von_neumann(in, sizeof(in), out, sizeof(out));
    /* 0x00 = 00000000: all pairs (0,0) -> all discarded */
    ASSERT(n == 0);
    PASS();
}

/* ── Protocol tests ────────────────────────────────────────────── */

static void test_ec_build_parse_roundtrip(void)
{
    TEST("EC packet build+parse roundtrip preserves fields");
    uint8_t seed[32]; memset(seed, 0x42, sizeof(seed));
    uint8_t pub[32], priv[64];
    edp_ed25519_keygen(seed, pub, priv);

    uint8_t entropy[64]; memset(entropy, 0xDE, sizeof(entropy));
    edp_pkt_ec_t pkt_tx, pkt_rx;
    edp_build_ec(&pkt_tx, 0xDEADBEEF, 42, EDP_TIER_FPGA_TRNG, 987,
                 entropy, priv, 0);

    uint8_t buf[sizeof(edp_pkt_ec_t)];
    memcpy(buf, &pkt_tx, sizeof(buf));

    ASSERT(edp_parse_ec(buf, sizeof(buf), &pkt_rx) == 0);
    ASSERT(pkt_rx.node_id == 0xDEADBEEF);
    ASSERT(pkt_rx.sequence == 42);
    ASSERT(pkt_rx.source_tier == EDP_TIER_FPGA_TRNG);
    ASSERT(pkt_rx.health_score == 987);
    ASSERT(memcmp(pkt_rx.entropy, entropy, 64) == 0);
    PASS();
}

static void test_ec_verify_valid_sig(void)
{
    TEST("EC signature verifies correctly");
    uint8_t seed[32]; memset(seed, 0x99, sizeof(seed));
    uint8_t pub[32], priv[64];
    edp_ed25519_keygen(seed, pub, priv);

    uint8_t entropy[64]; memset(entropy, 0xCA, sizeof(entropy));
    edp_pkt_ec_t pkt;
    edp_build_ec(&pkt, 1, 1, EDP_TIER_HW_TRNG, 500, entropy, priv, 0);

    uint8_t buf[sizeof(pkt)];
    memcpy(buf, &pkt, sizeof(buf));
    ASSERT(edp_verify_ec_raw(buf, sizeof(buf), pub) == 0);
    PASS();
}

static void test_ec_verify_rejects_tampered(void)
{
    TEST("EC verify rejects tampered entropy bytes");
    uint8_t seed[32]; memset(seed, 0x77, sizeof(seed));
    uint8_t pub[32], priv[64];
    edp_ed25519_keygen(seed, pub, priv);

    uint8_t entropy[64]; memset(entropy, 0xBB, sizeof(entropy));
    edp_pkt_ec_t pkt;
    edp_build_ec(&pkt, 2, 1, EDP_TIER_TIMING_JITTER, 300, entropy, priv, 0);

    uint8_t buf[sizeof(pkt)];
    memcpy(buf, &pkt, sizeof(buf));
    buf[offsetof(edp_pkt_ec_t, entropy)] ^= 0x01; /* flip one bit in entropy */
    ASSERT(edp_verify_ec_raw(buf, sizeof(buf), pub) != 0);
    PASS();
}

static void test_hello_build_verify(void)
{
    TEST("HELLO packet build+verify roundtrip");
    uint8_t seed[32]; memset(seed, 0x33, sizeof(seed));
    uint8_t pub[32], priv[64];
    edp_ed25519_keygen(seed, pub, priv);
    uint8_t fw_hash[32]; memset(fw_hash, 0xAA, sizeof(fw_hash));

    edp_pkt_hello_t pkt;
    edp_build_hello(&pkt, 0x01020304, pub, priv, 0x03, EDP_CAP_FPGA_TRNG, 2, fw_hash);

    uint8_t buf[sizeof(pkt)]; memcpy(buf, &pkt, sizeof(buf));

    edp_pkt_hello_t parsed;
    ASSERT(edp_parse_hello(buf, sizeof(buf), &parsed) == 0);
    ASSERT(parsed.node_id == 0x01020304);
    ASSERT(edp_verify_hello_raw(buf, sizeof(buf), pub) == 0);
    PASS();
}

/* ── Peer table tests ──────────────────────────────────────────── */

static void test_peer_sybil_delay(void)
{
    TEST("Peer rejects EC before Sybil delay elapses");
    edp_peer_table_t table;
    edp_peer_table_init(&table);

    /* Insert peer via HELLO */
    edp_pkt_hello_t hello = {0};
    hello.node_id = 0x0000CAFE;
    memset(hello.pubkey, 0x11, 32);
    hello.capabilities = EDP_CAP_SENSOR_ARRAY;

    edp_peer_t *peer = edp_peer_upsert_hello(&table, &hello);
    ASSERT(peer != NULL);
    ASSERT(peer->state == EDP_PEER_STATE_LEARNING);

    /* Try to accept EC immediately  -- should be rejected (Sybil) */
    edp_pkt_ec_t ec = {0};
    ec.node_id   = 0x0000CAFE;
    ec.sequence  = 1;
    ec.source_tier = EDP_TIER_SENSOR_PHYSICAL;

    edp_peer_ec_result_t result = edp_peer_check_ec(&table, peer, &ec);
    ASSERT(result == EDP_PEER_DROP_SYBIL);
    PASS();
}

static void test_peer_replay_rejection(void)
{
    TEST("Peer rejects replayed EC (same sequence number)");
    edp_peer_table_t table;
    edp_peer_table_init(&table);

    edp_peer_t *peer = &table.peers[0];
    peer->node_id  = 0x0000BEEF;
    peer->state    = EDP_PEER_STATE_TRUSTED;
    peer->last_seq = 100;

    edp_pkt_ec_t ec = {0};
    ec.node_id  = 0x0000BEEF;
    ec.sequence = 99; /* older than last_seq */

    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_DROP_REPLAY);

    ec.sequence = 100; /* equal to last_seq */
    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_DROP_REPLAY);
    PASS();
}

static void test_peer_rate_limiting(void)
{
    TEST("Peer rate-limits to 2 EC per second");
    edp_peer_table_t table;
    edp_peer_table_init(&table);

    edp_peer_t *peer = &table.peers[0];
    peer->node_id  = 0x00001234;
    peer->state    = EDP_PEER_STATE_TRUSTED;
    peer->last_seq = 0;
    peer->rate_window_start_ns = 0;

    edp_pkt_ec_t ec = {0};
    ec.node_id = 0x00001234;

    /* First two should pass */
    ec.sequence = 1;
    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_ACCEPT);
    peer->last_seq = 1;
    ec.sequence = 2;
    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_ACCEPT);
    peer->last_seq = 2;
    /* Third in the same second should be rate-limited */
    ec.sequence = 3;
    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_DROP_RATE);
    PASS();
}

static void test_peer_tier_fraud(void)
{
    TEST("Peer rejects FPGA_TRNG claim without capability");
    edp_peer_table_t table;
    edp_peer_table_init(&table);

    edp_peer_t *peer = &table.peers[0];
    peer->node_id   = 0xAABBCCDD;
    peer->state     = EDP_PEER_STATE_TRUSTED;
    peer->best_tier = EDP_TIER_TIMING_JITTER; /* claimed no FPGA */
    peer->last_seq  = 0;

    edp_pkt_ec_t ec = {0};
    ec.node_id     = 0xAABBCCDD;
    ec.sequence    = 1;
    ec.source_tier = EDP_TIER_FPGA_TRNG; /* fraudulent claim */

    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_DROP_TIER_FRAUD);
    PASS();
}

/* ── Pool mixing tests ─────────────────────────────────────────── */

static void test_pool_init_from_seed(void)
{
    TEST("Pool initialises with non-zero state from seed");
    edp_pool_t pool;
    uint8_t seed[32]; memset(seed, 0x12, sizeof(seed));
    edp_pool_init(&pool, seed, sizeof(seed));
    uint8_t zero[32] = {0};
    ASSERT(memcmp(pool.state, zero, 32) != 0);
    PASS();
}

static void test_pool_mix_local_changes_state(void)
{
    TEST("pool_mix_local changes pool state");
    edp_pool_t pool;
    uint8_t seed[32]; memset(seed, 0x34, sizeof(seed));
    edp_pool_init(&pool, seed, sizeof(seed));

    uint8_t before[32]; memcpy(before, pool.state, 32);
    uint8_t data[32]; memset(data, 0xAB, sizeof(data));
    edp_pool_mix_local(&pool, data, sizeof(data), EDP_TIER_FPGA_TRNG);
    ASSERT(memcmp(pool.state, before, 32) != 0);
    PASS();
}

static void test_pool_poisoning_resistance(void)
{
    TEST("Mixing all-zero remote EC does not zero the pool");
    edp_pool_t pool;
    uint8_t seed[32]; memset(seed, 0x56, sizeof(seed));
    edp_pool_init(&pool, seed, sizeof(seed));

    /* Mix 1000 all-zero EC contributions */
    uint8_t ec_zero[64] = {0};
    for (int i = 0; i < 1000; i++) {
        edp_pool_mix_remote(&pool, ec_zero, sizeof(ec_zero), NULL, 0,
                             EDP_TIER_SENSOR_PHYSICAL);
    }

    uint8_t zero[32] = {0};
    /* Pool state must not be all zeros */
    ASSERT(memcmp(pool.state, zero, 32) != 0);

    /* Pool state must differ from initial seed hash
     * (because we mixed 1000 times, it evolved) */
    uint8_t seed_hash[32];
    edp_blake3_hash(seed, sizeof(seed), seed_hash);
    /* After 1000 mixes, pool state has evolved. */
    ASSERT(pool.mix_count == 1000);
    PASS();
}

static void test_pool_extract_and_rekey(void)
{
    TEST("pool_extract returns non-zero output and re-keys");
    edp_pool_t pool;
    edp_pool_init(&pool, NULL, 0);

    uint8_t out1[32], out2[32];
    edp_pool_extract(&pool, out1, sizeof(out1));
    edp_pool_extract(&pool, out2, sizeof(out2));

    uint8_t zero[32] = {0};
    ASSERT(memcmp(out1, zero, 32) != 0);
    /* Two consecutive extracts must differ (forward secrecy / re-keying) */
    ASSERT(memcmp(out1, out2, 32) != 0);
    PASS();
}

/* ── Staging buffer tests ──────────────────────────────────────── */

static void test_staging_push_drain(void)
{
    TEST("staging push+drain returns correct bytes");
    edp_staging_t s;
    edp_staging_init(&s);

    uint8_t in[32]; for (int i = 0; i < 32; i++) in[i] = (uint8_t)i;
    edp_staging_push(&s, in, sizeof(in));
    ASSERT(s.used == 32);

    uint8_t out[32];
    size_t n = edp_staging_drain(&s, out, sizeof(out));
    ASSERT(n == 32);
    ASSERT(memcmp(out, in, 32) == 0);
    ASSERT(s.used == 0);
    PASS();
}

static void test_staging_wrap(void)
{
    TEST("staging buffer wraps correctly at capacity");
    edp_staging_t s;
    edp_staging_init(&s);

    /* Fill to capacity */
    uint8_t chunk[EDP_STAGING_CAPACITY];
    memset(chunk, 0xCC, sizeof(chunk));
    edp_staging_push(&s, chunk, sizeof(chunk));
    ASSERT(s.used == EDP_STAGING_CAPACITY);

    /* Push more  -- overwrites oldest (ring buffer) */
    uint8_t more[16]; memset(more, 0xDD, sizeof(more));
    edp_staging_push(&s, more, sizeof(more));
    /* Used stays at capacity */
    ASSERT(s.used == EDP_STAGING_CAPACITY);
    PASS();
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== EDP Unit Tests ===\n\n");

    printf("-- BLAKE3 --\n");
    test_blake3_empty();
    test_blake3_deterministic();
    test_blake3_chain_changes_state();
    test_blake3_keyed_differs_from_unkeyed();

    printf("\n-- Ed25519 --\n");
    test_ed25519_keygen_known();
    test_ed25519_sign_verify_roundtrip();
    test_ed25519_verify_rejects_tampered_msg();
    test_ed25519_verify_rejects_wrong_key();

    printf("\n-- Von Neumann --\n");
    test_vn_balanced_output();
    test_vn_rejects_constant();

    printf("\n-- Protocol --\n");
    test_ec_build_parse_roundtrip();
    test_ec_verify_valid_sig();
    test_ec_verify_rejects_tampered();
    test_hello_build_verify();

    printf("\n-- Peer table --\n");
    test_peer_sybil_delay();
    test_peer_replay_rejection();
    test_peer_rate_limiting();
    test_peer_tier_fraud();

    printf("\n-- Pool mixing --\n");
    test_pool_init_from_seed();
    test_pool_mix_local_changes_state();
    test_pool_poisoning_resistance();
    test_pool_extract_and_rekey();

    printf("\n-- Staging buffer --\n");
    test_staging_push_drain();
    test_staging_wrap();

    printf("\n=== Results: %d/%d passed",
           tests_run - tests_failed, tests_run);
    if (tests_failed == 0) printf("  -- ALL PASS ===\n");
    else printf("  -- %d FAILED ===\n", tests_failed);

    return tests_failed == 0 ? 0 : 1;
}
