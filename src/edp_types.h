/*
 * edp_types.h — EDP on-wire packet formats and internal types
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#pragma once

#include <stdint.h>
#include "../include/edp.h"

/* ── Packet types ──────────────────────────────────────────────── */
#define EDP_PKT_EC          0x1   /* Entropy Contribution */
#define EDP_PKT_HELLO       0x2   /* Node announcement */
#define EDP_PKT_HEALTH      0x3   /* Health-only update */
#define EDP_PKT_EPOCH_SYNC  0x4   /* PTP-synchronized injection trigger */
#define EDP_PKT_REVOKE      0x5   /* Key compromise notification */

#define EDP_PROTO_VERSION   1

/* ── Common header (first 4 bytes of every packet) ─────────────── */
/*
 * Byte 0: [7:4] = version, [3:0] = type
 * Byte 1: source_tier
 * Bytes 2-3: reserved
 */
#define EDP_HDR_VERSION(b0)   (((b0) >> 4) & 0xF)
#define EDP_HDR_TYPE(b0)      ((b0) & 0xF)
#define EDP_HDR_BYTE0(v, t)   ((uint8_t)(((v) << 4) | ((t) & 0xF)))

/* ── EC packet (Entropy Contribution) ─────────────────────────── */
/*
 * Total size: 4 + 4 + 4 + 8 + 2 + 2 + 64 + 64 = 152 bytes
 * Fits comfortably in a single UDP datagram.
 * Signature covers all fields except the signature field itself.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version_type;          /* EDP_HDR_BYTE0(1, EDP_PKT_EC) */
    uint8_t  source_tier;           /* edp_source_tier_t */
    uint16_t reserved;
    uint32_t node_id;
    uint32_t sequence;              /* monotonically increasing */
    uint64_t ptp_timestamp_ns;      /* 0 if PTP not available */
    uint16_t entropy_byte_count;    /* typically EDP_EC_ENTROPY_BYTES */
    uint16_t health_score;          /* 0–1000 */
    uint8_t  entropy[EDP_EC_ENTROPY_BYTES];
    uint8_t  signature[EDP_SIG_SIZE]; /* Ed25519 over all preceding bytes */
} edp_pkt_ec_t;
#pragma pack(pop)

#define EDP_PKT_EC_SIGNED_LEN  (sizeof(edp_pkt_ec_t) - EDP_SIG_SIZE)

/* ── HELLO packet ──────────────────────────────────────────────── */
/*
 * Total size: 4 + 4 + 32 + 1 + 2 + 1 + 32 + 64 = 140 bytes
 * Sent on boot and every HELLO_INTERVAL_MS.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version_type;
    uint8_t  reserved1;
    uint16_t reserved2;
    uint32_t node_id;
    uint8_t  pubkey[EDP_PUBKEY_SIZE];
    uint8_t  source_tiers_bitmap;   /* bit N set = Tier N source present */
    uint16_t capabilities;          /* see EDP_CAP_* below */
    uint8_t  num_sources;
    uint8_t  firmware_hash[EDP_FIRMWARE_HASH_SIZE];
    uint8_t  signature[EDP_SIG_SIZE];
} edp_pkt_hello_t;
#pragma pack(pop)

#define EDP_PKT_HELLO_SIGNED_LEN  (sizeof(edp_pkt_hello_t) - EDP_SIG_SIZE)

/* Capability flags */
#define EDP_CAP_PTP_CAPABLE     (1 << 0)
#define EDP_CAP_FPGA_TRNG       (1 << 1)
#define EDP_CAP_RISCV_SEED_CSR  (1 << 2)
#define EDP_CAP_SENSOR_ARRAY    (1 << 3)

/* ── REVOKE packet ─────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version_type;
    uint8_t  reserved1;
    uint16_t reserved2;
    uint32_t node_id;               /* node revoking itself */
    uint32_t sequence;
    uint8_t  reason;                /* 0=key_compromise, 1=rotation, 2=shutdown */
    uint8_t  new_pubkey[EDP_PUBKEY_SIZE]; /* if reason=rotation; else zeros */
    uint8_t  signature[EDP_SIG_SIZE];
} edp_pkt_revoke_t;
#pragma pack(pop)

/* ── EPOCH_SYNC packet (PTP companion) ─────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint8_t  version_type;
    uint8_t  reserved1;
    uint16_t reserved2;
    uint32_t node_id;               /* grandmaster node */
    uint32_t epoch_number;
    uint64_t epoch_start_ns;        /* PTP-synchronized epoch start time */
    uint32_t inject_offset_ms;      /* when to inject relative to epoch_start */
    uint8_t  signature[EDP_SIG_SIZE];
} edp_pkt_epoch_sync_t;
#pragma pack(pop)

/* ── Internal staging buffer ───────────────────────────────────── */
typedef struct {
    uint8_t  data[EDP_STAGING_CAPACITY];
    size_t   head;   /* next write position (wraps) */
    size_t   used;   /* bytes of valid data */
} edp_staging_t;

/* ── Internal pool state ───────────────────────────────────────── */
typedef struct {
    uint8_t  state[32];       /* BLAKE3 running hash state */
    uint64_t mix_count;
    uint64_t entropy_estimate; /* rough bits estimate, conservative */
} edp_pool_t;
