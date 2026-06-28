/*
 * edp_protocol.h — Packet encode, decode, and validate
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "edp_types.h"

int edp_build_ec(edp_pkt_ec_t *pkt, uint32_t node_id, uint32_t sequence,
                  edp_source_tier_t tier, uint16_t health_score,
                  const uint8_t entropy[EDP_EC_ENTROPY_BYTES],
                  const uint8_t privkey[EDP_PRIVKEY_SIZE], int ptp_enabled);

int edp_parse_ec(const uint8_t *buf, size_t len, edp_pkt_ec_t *out);
int edp_verify_ec(const edp_pkt_ec_t *pkt, const uint8_t pubkey[EDP_PUBKEY_SIZE]);
int edp_verify_ec_raw(const uint8_t *buf, size_t len,
                       const uint8_t pubkey[EDP_PUBKEY_SIZE]);

int edp_build_hello(edp_pkt_hello_t *pkt, uint32_t node_id,
                     const uint8_t pubkey[EDP_PUBKEY_SIZE],
                     const uint8_t privkey[EDP_PRIVKEY_SIZE],
                     uint8_t source_tiers_bitmap, uint16_t capabilities,
                     uint8_t num_sources,
                     const uint8_t firmware_hash[EDP_FIRMWARE_HASH_SIZE]);

int edp_parse_hello(const uint8_t *buf, size_t len, edp_pkt_hello_t *out);
int edp_verify_hello_raw(const uint8_t *buf, size_t len,
                          const uint8_t pubkey[EDP_PUBKEY_SIZE]);

int edp_build_revoke(edp_pkt_revoke_t *pkt, uint32_t node_id, uint32_t sequence,
                      uint8_t reason, const uint8_t new_pubkey[EDP_PUBKEY_SIZE],
                      const uint8_t privkey[EDP_PRIVKEY_SIZE]);
