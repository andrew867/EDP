/*
 * edp_protocol.c — Packet encode, decode, and validate
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#include "edp_protocol.h"
#include "edp_crypto.h"
#include <string.h>
#include <arpa/inet.h>  /* htonl/ntohl */
#include <time.h>

/* ── Helpers ───────────────────────────────────────────────────── */

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── EC packet ─────────────────────────────────────────────────── */

int edp_build_ec(edp_pkt_ec_t *pkt,
                  uint32_t node_id,
                  uint32_t sequence,
                  edp_source_tier_t tier,
                  uint16_t health_score,
                  const uint8_t entropy[EDP_EC_ENTROPY_BYTES],
                  const uint8_t privkey[EDP_PRIVKEY_SIZE],
                  int ptp_enabled)
{
    memset(pkt, 0, sizeof(*pkt));

    pkt->version_type      = EDP_HDR_BYTE0(EDP_PROTO_VERSION, EDP_PKT_EC);
    pkt->source_tier       = (uint8_t)tier;
    pkt->reserved          = 0;
    pkt->node_id           = htonl(node_id);
    pkt->sequence          = htonl(sequence);
    pkt->ptp_timestamp_ns  = ptp_enabled ? monotonic_ns() : 0; /* KNOWN LIMITATION: full PTP sync not yet implemented; uses local monotonic clock */
    pkt->entropy_byte_count = htons(EDP_EC_ENTROPY_BYTES);
    pkt->health_score      = htons(health_score);
    memcpy(pkt->entropy, entropy, EDP_EC_ENTROPY_BYTES);

    /* Sign everything except the signature field */
    edp_ed25519_sign(privkey,
                     (const uint8_t *)pkt,
                     EDP_PKT_EC_SIGNED_LEN,
                     pkt->signature);
    return 0;
}

int edp_parse_ec(const uint8_t *buf, size_t len, edp_pkt_ec_t *out)
{
    if (len < sizeof(edp_pkt_ec_t)) return -1;
    if (EDP_HDR_VERSION(buf[0]) != EDP_PROTO_VERSION) return -1;
    if (EDP_HDR_TYPE(buf[0]) != EDP_PKT_EC) return -1;

    memcpy(out, buf, sizeof(edp_pkt_ec_t));

    /* Byte-order corrections */
    out->node_id           = ntohl(out->node_id);
    out->sequence          = ntohl(out->sequence);
    out->entropy_byte_count = ntohs(out->entropy_byte_count);
    out->health_score      = ntohs(out->health_score);

    if (out->entropy_byte_count > EDP_EC_ENTROPY_BYTES) return -1;
    return 0;
}

int edp_verify_ec(const edp_pkt_ec_t *pkt,
                   const uint8_t pubkey[EDP_PUBKEY_SIZE])
{
    /*
     * Reconstruct the host-order packet as it was before signing.
     * The packet was built with network-byte-order fields, so we
     * need to verify against the raw buffer (as received), not the
     * parsed struct.
     *
     * This is slightly awkward; in practice the verification is done
     * on the raw buffer before parsing. We provide a helper below.
     */
    edp_pkt_ec_t wire;
    memcpy(&wire, pkt, sizeof(wire));
    /* Re-apply network byte order for the fields we parsed */
    wire.node_id            = htonl(pkt->node_id);
    wire.sequence           = htonl(pkt->sequence);
    wire.entropy_byte_count = htons(pkt->entropy_byte_count);
    wire.health_score       = htons(pkt->health_score);

    return edp_ed25519_verify(pubkey,
                               (const uint8_t *)&wire,
                               EDP_PKT_EC_SIGNED_LEN,
                               wire.signature);
}

int edp_verify_ec_raw(const uint8_t *buf, size_t len,
                       const uint8_t pubkey[EDP_PUBKEY_SIZE])
{
    if (len < sizeof(edp_pkt_ec_t)) return -1;
    return edp_ed25519_verify(pubkey,
                               buf,
                               EDP_PKT_EC_SIGNED_LEN,
                               buf + EDP_PKT_EC_SIGNED_LEN);
}

/* ── HELLO packet ──────────────────────────────────────────────── */

int edp_build_hello(edp_pkt_hello_t *pkt,
                     uint32_t node_id,
                     const uint8_t pubkey[EDP_PUBKEY_SIZE],
                     const uint8_t privkey[EDP_PRIVKEY_SIZE],
                     uint8_t source_tiers_bitmap,
                     uint16_t capabilities,
                     uint8_t num_sources,
                     const uint8_t firmware_hash[EDP_FIRMWARE_HASH_SIZE])
{
    memset(pkt, 0, sizeof(*pkt));
    pkt->version_type       = EDP_HDR_BYTE0(EDP_PROTO_VERSION, EDP_PKT_HELLO);
    pkt->node_id            = htonl(node_id);
    memcpy(pkt->pubkey, pubkey, EDP_PUBKEY_SIZE);
    pkt->source_tiers_bitmap = source_tiers_bitmap;
    pkt->capabilities       = htons(capabilities);
    pkt->num_sources        = num_sources;
    memcpy(pkt->firmware_hash, firmware_hash, EDP_FIRMWARE_HASH_SIZE);

    edp_ed25519_sign(privkey,
                     (const uint8_t *)pkt,
                     EDP_PKT_HELLO_SIGNED_LEN,
                     pkt->signature);
    return 0;
}

int edp_parse_hello(const uint8_t *buf, size_t len, edp_pkt_hello_t *out)
{
    if (len < sizeof(edp_pkt_hello_t)) return -1;
    if (EDP_HDR_VERSION(buf[0]) != EDP_PROTO_VERSION) return -1;
    if (EDP_HDR_TYPE(buf[0]) != EDP_PKT_HELLO) return -1;
    memcpy(out, buf, sizeof(edp_pkt_hello_t));
    out->node_id      = ntohl(out->node_id);
    out->capabilities = ntohs(out->capabilities);
    return 0;
}

int edp_verify_hello_raw(const uint8_t *buf, size_t len,
                          const uint8_t pubkey[EDP_PUBKEY_SIZE])
{
    if (len < sizeof(edp_pkt_hello_t)) return -1;
    return edp_ed25519_verify(pubkey,
                               buf,
                               EDP_PKT_HELLO_SIGNED_LEN,
                               buf + EDP_PKT_HELLO_SIGNED_LEN);
}

/* ── REVOKE packet ─────────────────────────────────────────────── */

int edp_build_revoke(edp_pkt_revoke_t *pkt,
                      uint32_t node_id,
                      uint32_t sequence,
                      uint8_t reason,
                      const uint8_t new_pubkey[EDP_PUBKEY_SIZE],
                      const uint8_t privkey[EDP_PRIVKEY_SIZE])
{
    memset(pkt, 0, sizeof(*pkt));
    pkt->version_type = EDP_HDR_BYTE0(EDP_PROTO_VERSION, EDP_PKT_REVOKE);
    pkt->node_id      = htonl(node_id);
    pkt->sequence     = htonl(sequence);
    pkt->reason       = reason;
    if (new_pubkey && reason == 1)
        memcpy(pkt->new_pubkey, new_pubkey, EDP_PUBKEY_SIZE);

    edp_ed25519_sign(privkey,
                     (const uint8_t *)pkt,
                     sizeof(edp_pkt_revoke_t) - EDP_SIG_SIZE,
                     pkt->signature);
    return 0;
}
