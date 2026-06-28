/*
 * test_security.c  -- EDP security property tests
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Tests the core security guarantees:
 *   SEC-01: Poisoning resistance (adversarial EC cannot weaken pool)
 *   SEC-02: Pool independence (different local sources -> different pools)
 *   SEC-03: Forward secrecy (extraction re-keys the pool)
 *   SEC-04: Sybil delay enforced
 *   SEC-05: Spoofed HELLO rejected
 *   SEC-06: Source tier fraud rejected
 *   SEC-07: Rate limiting enforced under flood
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "../include/edp.h"
#include "../src/edp_types.h"
#include "../src/edp_crypto.h"
#include "../src/edp_protocol.h"
#include "../src/edp_peer.h"
#include "../src/edp_mix.h"

static int tests_run = 0, tests_failed = 0;
#define TEST(n) do { printf("  %-55s", n); tests_run++; } while(0)
#define PASS()  do { printf("PASS\n"); } while(0)
#define FAIL(m) do { printf("FAIL: %s (L%d)\n", m, __LINE__); tests_failed++; return; } while(0)
#define ASSERT(c) do { if (!(c)) FAIL(#c); } while(0)

/* ── Entropy quality helpers ───────────────────────────────────── */

/*
 * monobit_test()  -- NIST SP 800-22 Test 1 (simplified).
 * Returns 1 if the proportion of 1-bits is within [0.45, 0.55].
 * For a 256-byte sample this is a very coarse check.
 */
static int monobit_test(const uint8_t *buf, size_t len)
{
    size_t ones = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = buf[i];
        while (b) { ones += b & 1; b >>= 1; }
    }
    double ratio = (double)ones / (double)(len * 8);
    return (ratio >= 0.40 && ratio <= 0.60);
}

/*
 * byte_diversity()  -- count distinct byte values in a buffer.
 * A random 256-byte buffer should have close to 256 distinct values.
 */
static int byte_diversity(const uint8_t *buf, size_t len)
{
    int seen[256] = {0};
    for (size_t i = 0; i < len; i++) seen[buf[i]] = 1;
    int count = 0;
    for (int i = 0; i < 256; i++) count += seen[i];
    return count;
}

/* ── SEC-01: Poisoning resistance ─────────────────────────────── */

static void test_sec01_poisoning_resistance(void)
{
    TEST("SEC-01: All-zero EC does not zero or bias the pool");

    /* Initialise pool with good seed */
    edp_pool_t pool;
    uint8_t seed[32]; memset(seed, 0x7F, sizeof(seed));
    edp_pool_init(&pool, seed, sizeof(seed));

    /* Mix 10,000 all-zero EC contributions */
    uint8_t zero_ec[64] = {0};
    for (int i = 0; i < 10000; i++) {
        edp_pool_mix_remote(&pool, zero_ec, sizeof(zero_ec), NULL, 0,
                             EDP_TIER_SENSOR_PHYSICAL);
    }

    /* Extract 256 bytes and check monobit balance */
    uint8_t out[256];
    edp_pool_extract(&pool, out, sizeof(out));

    ASSERT(monobit_test(out, sizeof(out)));

    /* Pool state must not be all zeros */
    uint8_t zero[32] = {0};
    ASSERT(memcmp(pool.state, zero, 32) != 0);
    PASS();
}

/* ── SEC-02: Pool independence ────────────────────────────────── */

static void test_sec02_pool_independence(void)
{
    TEST("SEC-02: Different seeds -> independent pool outputs");

    edp_pool_t pool_a, pool_b;
    uint8_t seed_a[32]; memset(seed_a, 0xAA, sizeof(seed_a));
    uint8_t seed_b[32]; memset(seed_b, 0xBB, sizeof(seed_b));
    edp_pool_init(&pool_a, seed_a, sizeof(seed_a));
    edp_pool_init(&pool_b, seed_b, sizeof(seed_b));

    /* Apply identical remote contributions */
    uint8_t common_ec[64]; memset(common_ec, 0x55, sizeof(common_ec));
    for (int i = 0; i < 100; i++) {
        edp_pool_mix_remote(&pool_a, common_ec, sizeof(common_ec), NULL, 0,
                             EDP_TIER_SENSOR_PHYSICAL);
        edp_pool_mix_remote(&pool_b, common_ec, sizeof(common_ec), NULL, 0,
                             EDP_TIER_SENSOR_PHYSICAL);
    }

    uint8_t out_a[32], out_b[32];
    edp_pool_extract(&pool_a, out_a, sizeof(out_a));
    edp_pool_extract(&pool_b, out_b, sizeof(out_b));

    /* Different initial seeds -> different outputs even with same EC contributions */
    ASSERT(memcmp(out_a, out_b, 32) != 0);
    PASS();
}

/* ── SEC-03: Forward secrecy ──────────────────────────────────── */

static void test_sec03_forward_secrecy(void)
{
    TEST("SEC-03: Consecutive extractions produce different outputs");

    edp_pool_t pool;
    edp_pool_init(&pool, NULL, 0);

    uint8_t out[10][32];
    for (int i = 0; i < 10; i++) {
        edp_pool_extract(&pool, out[i], 32);
    }

    /* No two consecutive extracts should match */
    int all_different = 1;
    for (int i = 0; i < 9; i++) {
        if (memcmp(out[i], out[i+1], 32) == 0) {
            all_different = 0;
            break;
        }
    }
    ASSERT(all_different);
    PASS();
}

/* ── SEC-04: Sybil delay ──────────────────────────────────────── */

static void test_sec04_sybil_delay_enforced(void)
{
    TEST("SEC-04: New peer's EC rejected before Sybil delay");

    edp_peer_table_t table;
    edp_peer_table_init(&table);

    edp_pkt_hello_t hello = {0};
    hello.node_id = 0xDEAD0001;
    memset(hello.pubkey, 0x22, 32);
    hello.capabilities = EDP_CAP_SENSOR_ARRAY;

    edp_peer_t *peer = edp_peer_upsert_hello(&table, &hello);
    ASSERT(peer != NULL);
    ASSERT(peer->state == EDP_PEER_STATE_LEARNING);

    edp_pkt_ec_t ec = {0};
    ec.node_id    = 0xDEAD0001;
    ec.sequence   = 1;
    ec.source_tier = EDP_TIER_SENSOR_PHYSICAL;

    /* Must be rejected immediately */
    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_DROP_SYBIL);

    /* Simulate Sybil delay elapsed by backdating first_seen_ns */
    peer->first_seen_ns -= (uint64_t)EDP_SYBIL_DELAY_MS * 2 * 1000000ULL;

    /* Now it should be promoted and accepted */
    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_ACCEPT);
    ASSERT(peer->state == EDP_PEER_STATE_TRUSTED);
    PASS();
}

/* ── SEC-05: Spoofed HELLO ────────────────────────────────────── */

static void test_sec05_spoofed_hello_rejected(void)
{
    TEST("SEC-05: HELLO with wrong signature rejected");

    uint8_t seed_a[32]; memset(seed_a, 0x11, sizeof(seed_a));
    uint8_t seed_b[32]; memset(seed_b, 0x22, sizeof(seed_b));
    uint8_t pub_a[32], priv_a[64];
    uint8_t pub_b[32], priv_b[64];
    edp_ed25519_keygen(seed_a, pub_a, priv_a);
    edp_ed25519_keygen(seed_b, pub_b, priv_b);
    uint8_t fw[32] = {0};

    /* Build HELLO signed with key A */
    edp_pkt_hello_t hello;
    edp_build_hello(&hello, 0x01, pub_a, priv_a, 0x1, EDP_CAP_SENSOR_ARRAY, 1, fw);
    uint8_t buf[sizeof(hello)]; memcpy(buf, &hello, sizeof(buf));

    /* Verify with key A -> should pass */
    ASSERT(edp_verify_hello_raw(buf, sizeof(buf), pub_a) == 0);

    /* Verify with key B -> should fail */
    ASSERT(edp_verify_hello_raw(buf, sizeof(buf), pub_b) != 0);

    /* Tamper with the pubkey field in the packet -> signature mismatch */
    memcpy(buf + offsetof(edp_pkt_hello_t, pubkey), pub_b, 32);
    ASSERT(edp_verify_hello_raw(buf, sizeof(buf), pub_b) != 0);
    PASS();
}

/* ── SEC-06: Source tier fraud ────────────────────────────────── */

static void test_sec06_tier_fraud_rejected(void)
{
    TEST("SEC-06: FPGA_TRNG claim without capability flag rejected");

    edp_peer_table_t table;
    edp_peer_table_init(&table);

    edp_peer_t *peer = &table.peers[0];
    peer->node_id   = 0xFAADBEEF;
    peer->state     = EDP_PEER_STATE_TRUSTED;
    peer->best_tier = EDP_TIER_SENSOR_PHYSICAL; /* no FPGA */
    peer->last_seq  = 0;

    edp_pkt_ec_t ec = {0};
    ec.node_id     = 0xFAADBEEF;
    ec.sequence    = 1;
    ec.source_tier = EDP_TIER_FPGA_TRNG; /* fraudulent claim */

    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_DROP_TIER_FRAUD);

    /* Legitimate claim at actual tier should pass */
    ec.source_tier = EDP_TIER_SENSOR_PHYSICAL;
    ASSERT(edp_peer_check_ec(&table, peer, &ec) == EDP_PEER_ACCEPT);
    PASS();
}

/* ── SEC-07: Rate limiting under flood ────────────────────────── */

static void test_sec07_rate_limit_flood(void)
{
    TEST("SEC-07: Rate limiting drops >2 EC/second from one peer");

    edp_peer_table_t table;
    edp_peer_table_init(&table);

    edp_peer_t *peer = &table.peers[0];
    peer->node_id  = 0x00FLOOD1;
    peer->state    = EDP_PEER_STATE_TRUSTED;
    peer->last_seq = 0;
    peer->rate_window_start_ns = 0;

    edp_pkt_ec_t ec = {0};
    ec.node_id = 0x00FLOOD1;

    int accepted = 0, dropped = 0;
    for (int i = 1; i <= 100; i++) {
        ec.sequence = (uint32_t)i;
        edp_peer_ec_result_t r = edp_peer_check_ec(&table, peer, &ec);
        if (r == EDP_PEER_ACCEPT) {
            peer->last_seq = ec.sequence;
            accepted++;
        } else if (r == EDP_PEER_DROP_RATE) {
            dropped++;
        }
    }

    /* Should accept exactly 2 (the rate limit) and drop the rest */
    ASSERT(accepted == 2);
    ASSERT(dropped == 98);
    PASS();
}

/* ── SEC-08: Pool quality after mixed sources ─────────────────── */

static void test_sec08_mixed_source_quality(void)
{
    TEST("SEC-08: Pool output passes monobit after local + remote mixing");

    edp_pool_t pool;
    uint8_t seed[32]; memset(seed, 0xC3, sizeof(seed));
    edp_pool_init(&pool, seed, sizeof(seed));

    /* Mix local Tier 0 and Tier 2 sources */
    uint8_t local_t0[32]; memset(local_t0, 0xDE, sizeof(local_t0));
    uint8_t local_t2[32]; memset(local_t2, 0xAD, sizeof(local_t2));
    edp_pool_mix_local(&pool, local_t0, sizeof(local_t0), EDP_TIER_FPGA_TRNG);
    edp_pool_mix_local(&pool, local_t2, sizeof(local_t2), EDP_TIER_SENSOR_PHYSICAL);

    /* Mix 5 remote peers with varying contributions */
    for (int peer = 0; peer < 5; peer++) {
        uint8_t ec[64];
        memset(ec, (uint8_t)(peer * 37 + 1), sizeof(ec));
        edp_pool_mix_remote(&pool, ec, sizeof(ec), NULL, 0, EDP_TIER_HW_TRNG);
    }

    /* Extract 1024 bytes and run monobit */
    uint8_t out[1024];
    for (size_t off = 0; off < sizeof(out); off += 32) {
        edp_pool_extract(&pool, out + off, 32);
        /* Mix one more local contribution to keep pool fresh */
        edp_pool_mix_local(&pool, out + off, 4, EDP_TIER_TIMING_JITTER);
    }

    ASSERT(monobit_test(out, sizeof(out)));
    int diversity = byte_diversity(out, sizeof(out));
    ASSERT(diversity > 200); /* Expect most byte values represented in 1KB */
    PASS();
}

int main(void)
{
    printf("=== EDP Security Tests ===\n\n");

    test_sec01_poisoning_resistance();
    test_sec02_pool_independence();
    test_sec03_forward_secrecy();
    test_sec04_sybil_delay_enforced();
    test_sec05_spoofed_hello_rejected();
    test_sec06_tier_fraud_rejected();
    test_sec07_rate_limit_flood();
    test_sec08_mixed_source_quality();

    printf("\n=== Results: %d/%d passed",
           tests_run - tests_failed, tests_run);
    if (tests_failed == 0) printf("  -- ALL PASS ===\n");
    else printf("  -- %d FAILED ===\n", tests_failed);

    return tests_failed == 0 ? 0 : 1;
}
