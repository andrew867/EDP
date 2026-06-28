/*
 * edp_peer.c — Peer table management
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#include "edp_peer.h"
#include "edp_crypto.h"
#include <string.h>
#include <time.h>

#define RATE_WINDOW_NS  (1000000000ULL) /* 1 second */
#define RATE_LIMIT_COUNT  2             /* max EC packets accepted per window */

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void edp_peer_table_init(edp_peer_table_t *t)
{
    memset(t, 0, sizeof(*t));
}

edp_peer_t *edp_peer_find(edp_peer_table_t *t, uint32_t node_id)
{
    for (int i = 0; i < EDP_MAX_PEERS; i++) {
        if (t->peers[i].node_id == node_id &&
            t->peers[i].state != EDP_PEER_STATE_UNKNOWN)
            return &t->peers[i];
    }
    return NULL;
}

edp_peer_t *edp_peer_upsert_hello(edp_peer_table_t *t,
                                    const edp_pkt_hello_t *hello)
{
    uint64_t ts = now_ns();
    edp_peer_t *peer = edp_peer_find(t, hello->node_id);

    if (!peer) {
        /* Find an empty slot */
        for (int i = 0; i < EDP_MAX_PEERS; i++) {
            if (t->peers[i].state == EDP_PEER_STATE_UNKNOWN) {
                peer = &t->peers[i];
                break;
            }
        }
        /* If table is full, evict the oldest OFFLINE peer */
        if (!peer) {
            uint64_t oldest = UINT64_MAX;
            for (int i = 0; i < EDP_MAX_PEERS; i++) {
                if (t->peers[i].state == EDP_PEER_STATE_OFFLINE &&
                    t->peers[i].last_seen_ns < oldest) {
                    oldest = t->peers[i].last_seen_ns;
                    peer = &t->peers[i];
                }
            }
        }
        if (!peer) return NULL; /* table full, no evictable slot */

        memset(peer, 0, sizeof(*peer));
        peer->node_id       = hello->node_id;
        peer->first_seen_ns = ts;
        peer->state         = EDP_PEER_STATE_LEARNING;
        t->count++;
    }

    memcpy(peer->pubkey, hello->pubkey, EDP_PUBKEY_SIZE);
    peer->last_seen_ns = ts;

    /* Determine best tier from capability bitmap */
    if (hello->capabilities & EDP_CAP_FPGA_TRNG)
        peer->best_tier = EDP_TIER_FPGA_TRNG;
    else if (hello->capabilities & EDP_CAP_RISCV_SEED_CSR)
        peer->best_tier = EDP_TIER_HW_TRNG;
    else if (hello->capabilities & EDP_CAP_SENSOR_ARRAY)
        peer->best_tier = EDP_TIER_SENSOR_PHYSICAL;
    else
        peer->best_tier = EDP_TIER_TIMING_JITTER;

    /* Promote to TRUSTED if Sybil delay has elapsed */
    if (peer->state == EDP_PEER_STATE_LEARNING) {
        uint64_t age_ms = (ts - peer->first_seen_ns) / 1000000ULL;
        if (age_ms >= EDP_SYBIL_DELAY_MS) {
            peer->state = EDP_PEER_STATE_TRUSTED;
            if (t->on_state_change)
                t->on_state_change(peer->node_id, EDP_PEER_STATE_TRUSTED);
        }
    }
    return peer;
}

/*
 * edp_peer_check_ec() — Validate an incoming EC from a peer.
 * Returns EDP_PEER_ACCEPT on success, or EDP_PEER_DROP_* error code.
 */
edp_peer_ec_result_t edp_peer_check_ec(edp_peer_table_t *t,
                                        edp_peer_t *peer,
                                        const edp_pkt_ec_t *ec)
{
    uint64_t ts = now_ns();

    if (!peer) return EDP_PEER_DROP_UNKNOWN;
    if (peer->state == EDP_PEER_STATE_UNTRUSTED) return EDP_PEER_DROP_UNTRUSTED;
    if (peer->state == EDP_PEER_STATE_OFFLINE)   return EDP_PEER_DROP_OFFLINE;
    if (peer->state == EDP_PEER_STATE_UNKNOWN)   return EDP_PEER_DROP_UNKNOWN;

    /* Sybil delay: reject EC from newly-seen nodes */
    if (peer->state == EDP_PEER_STATE_LEARNING) {
        uint64_t age_ms = (ts - peer->first_seen_ns) / 1000000ULL;
        if (age_ms < EDP_SYBIL_DELAY_MS)
            return EDP_PEER_DROP_SYBIL;
        /* Promote now */
        peer->state = EDP_PEER_STATE_TRUSTED;
        if (t->on_state_change)
            t->on_state_change(peer->node_id, EDP_PEER_STATE_TRUSTED);
    }

    /* Replay check: sequence must be strictly greater than last seen */
    if (ec->sequence <= peer->last_seq && peer->last_seq != 0)
        return EDP_PEER_DROP_REPLAY;

    /* Rate limiting: max RATE_LIMIT_COUNT per RATE_WINDOW_NS */
    if (ts - peer->rate_window_start_ns >= RATE_WINDOW_NS) {
        /* New window */
        peer->rate_window_start_ns = ts;
        peer->rate_count = 0;
    }
    peer->rate_count++;
    if (peer->rate_count > RATE_LIMIT_COUNT)
        return EDP_PEER_DROP_RATE;

    /* Source tier fraud: reject FPGA_TRNG claims without capability flag */
    if (ec->source_tier == EDP_TIER_FPGA_TRNG &&
        peer->best_tier != EDP_TIER_FPGA_TRNG)
        return EDP_PEER_DROP_TIER_FRAUD;

    return EDP_PEER_ACCEPT;
}

void edp_peer_record_ec(edp_peer_t *peer, const edp_pkt_ec_t *ec)
{
    peer->last_seq        = ec->sequence;
    peer->last_seen_ns    = now_ns();
    peer->health_score    = ec->health_score;
    peer->ec_recv_count++;
}

void edp_peer_record_drop(edp_peer_t *peer)
{
    if (peer) peer->ec_drop_count++;
}

void edp_peer_revoke(edp_peer_table_t *t, uint32_t node_id)
{
    edp_peer_t *peer = edp_peer_find(t, node_id);
    if (peer) {
        peer->state = EDP_PEER_STATE_UNTRUSTED;
        edp_wipe(peer->pubkey, EDP_PUBKEY_SIZE); /* discard old key */
        if (t->on_state_change)
            t->on_state_change(node_id, EDP_PEER_STATE_UNTRUSTED);
    }
}

void edp_peer_tick(edp_peer_table_t *t,
                    void (*on_offline)(uint32_t node_id))
{
    uint64_t ts    = now_ns();
    uint64_t limit = (uint64_t)EDP_PEER_TIMEOUT_MS * 1000000ULL;

    for (int i = 0; i < EDP_MAX_PEERS; i++) {
        edp_peer_t *p = &t->peers[i];
        if (p->state != EDP_PEER_STATE_TRUSTED &&
            p->state != EDP_PEER_STATE_LEARNING) continue;

        if (ts - p->last_seen_ns > limit) {
            edp_peer_state_t old = p->state;
            p->state = EDP_PEER_STATE_OFFLINE;
            if (old != EDP_PEER_STATE_OFFLINE) {
                if (t->on_state_change)
                    t->on_state_change(p->node_id, EDP_PEER_STATE_OFFLINE);
                if (on_offline) on_offline(p->node_id);
            }
        }
    }
}

uint32_t edp_peer_count_online(const edp_peer_table_t *t)
{
    uint32_t n = 0;
    for (int i = 0; i < EDP_MAX_PEERS; i++) {
        if (t->peers[i].state == EDP_PEER_STATE_TRUSTED) n++;
    }
    return n;
}
