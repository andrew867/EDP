/*
 * edp_peer.h  -- Peer table management
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#pragma once

#include "edp_types.h"
#include "../include/edp.h"

typedef struct {
    edp_peer_t   peers[EDP_MAX_PEERS];
    int          count;
    void (*on_state_change)(uint32_t node_id, edp_peer_state_t new_state);
} edp_peer_table_t;

typedef enum {
    EDP_PEER_ACCEPT         = 0,
    EDP_PEER_DROP_UNKNOWN   = 1,
    EDP_PEER_DROP_UNTRUSTED = 2,
    EDP_PEER_DROP_OFFLINE   = 3,
    EDP_PEER_DROP_REPLAY    = 4,
    EDP_PEER_DROP_RATE      = 5,
    EDP_PEER_DROP_SYBIL     = 6,
    EDP_PEER_DROP_TIER_FRAUD = 7,
} edp_peer_ec_result_t;

void          edp_peer_table_init(edp_peer_table_t *t);
edp_peer_t   *edp_peer_find(edp_peer_table_t *t, uint32_t node_id);
edp_peer_t   *edp_peer_upsert_hello(edp_peer_table_t *t, const edp_pkt_hello_t *hello);
edp_peer_ec_result_t edp_peer_check_ec(edp_peer_table_t *t,
                                        edp_peer_t *peer,
                                        const edp_pkt_ec_t *ec);
void  edp_peer_record_ec(edp_peer_t *peer, const edp_pkt_ec_t *ec);
void  edp_peer_record_drop(edp_peer_t *peer);
void  edp_peer_revoke(edp_peer_table_t *t, uint32_t node_id);
void  edp_peer_tick(edp_peer_table_t *t, void (*on_offline)(uint32_t node_id));
uint32_t edp_peer_count_online(const edp_peer_table_t *t);
