/*
 * edp.h  -- Entropy Distribution Protocol public API
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * EDP is a peer-to-peer entropy augmentation protocol for closed-loop
 * embedded mesh networks. Every node is simultaneously a producer and
 * consumer of entropy. External contributions are BLAKE3-chained into
 * the local pool  -- they can only add entropy, never reduce it.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* ── Version ───────────────────────────────────────────────────── */
#define EDP_VERSION_MAJOR  0
#define EDP_VERSION_MINOR  1
#define EDP_VERSION_PATCH  0

/* ── Network constants ─────────────────────────────────────────── */
/* Port 4086: aspirational homage to RFC 4086 (Randomness Requirements for Security).
 * NOT an IANA-assigned port. IANA lists 4086/tcp as Reserved.
 * Use EDP_PORT env var or --port flag to override in production deployments. */
#define EDP_UDP_PORT            4086
#define EDP_MULTICAST_GROUP     "224.0.86.1"    /* provisional */
#define EDP_MULTICAST_TTL       1               /* link-local only */

/* ── Timing (milliseconds) ─────────────────────────────────────── */
#define EDP_BROADCAST_INTERVAL_MS   1000
#define EDP_HELLO_INTERVAL_MS       30000
#define EDP_HARVEST_INTERVAL_MS     100
#define EDP_PEER_TIMEOUT_MS         3500        /* 3 missed heartbeats */
#define EDP_SYBIL_DELAY_MS          30000       /* min age before EC accepted */

/* ── Sizes ─────────────────────────────────────────────────────── */
#define EDP_NODE_ID_SIZE            4
#define EDP_PUBKEY_SIZE             32          /* Ed25519 public key */
#define EDP_PRIVKEY_SIZE            64          /* Ed25519 private key */
#define EDP_SIG_SIZE                64          /* Ed25519 signature */
#define EDP_EC_ENTROPY_BYTES        64          /* bytes per contribution */
#define EDP_STAGING_CAPACITY        512         /* bytes in staging buffer */
#define EDP_MAX_PEERS               16
#define EDP_MAX_SOURCES             8
#define EDP_SOURCE_NAME_LEN         32
#define EDP_FIRMWARE_HASH_SIZE      32          /* BLAKE3 of OCU firmware */

/* ── Source quality tiers ──────────────────────────────────────── */
typedef enum {
    EDP_TIER_FPGA_TRNG       = 0,   /* Ring-oscillator TRNG in FPGA fabric */
    EDP_TIER_HW_TRNG         = 1,   /* RISC-V Seed CSR or on-chip TRNG */
    EDP_TIER_SENSOR_PHYSICAL = 2,   /* IMU, encoder jitter, CAN timing, mic */
    EDP_TIER_TIMING_JITTER   = 3,   /* HAVEGE-style execution timing */
    EDP_TIER_UNKNOWN         = 0xFF  /* Unverified; contributions rejected */
} edp_source_tier_t;

/* ── Peer states ───────────────────────────────────────────────── */
typedef enum {
    EDP_PEER_STATE_UNKNOWN    = 0,
    EDP_PEER_STATE_LEARNING   = 1,   /* Seen HELLO; within SYBIL_DELAY window */
    EDP_PEER_STATE_TRUSTED    = 2,   /* HELLO age > SYBIL_DELAY; EC accepted */
    EDP_PEER_STATE_UNTRUSTED  = 3,   /* REVOKE received or tier fraud detected */
    EDP_PEER_STATE_OFFLINE    = 4,   /* No heartbeat for PEER_TIMEOUT */
} edp_peer_state_t;

/* ── Entropy source descriptor ─────────────────────────────────── */
typedef struct edp_source {
    char              name[EDP_SOURCE_NAME_LEN];
    edp_source_tier_t tier;
    /*
     * harvest()  -- collect raw entropy bytes from this source.
     * Called every HARVEST_INTERVAL_MS. Should be non-blocking.
     * Returns number of bytes written to buf, or -1 on error.
     */
    int  (*harvest)(uint8_t *buf, size_t len, void *ctx);
    void             *ctx;           /* platform-specific context */
    uint16_t          health_score;  /* 0-1000; updated by daemon */
    uint64_t          bits_total;    /* cumulative bits harvested */
    uint64_t          last_harvest;  /* monotonic ns timestamp */
    uint8_t           conditioning_key[32]; /* per-source BLAKE3 key */
} edp_source_t;

/* ── Peer table entry ──────────────────────────────────────────── */
typedef struct edp_peer {
    uint32_t           node_id;
    uint8_t            pubkey[EDP_PUBKEY_SIZE];
    uint32_t           last_seq;
    uint64_t           first_seen_ns;   /* for Sybil delay */
    uint64_t           last_seen_ns;
    edp_peer_state_t   state;
    edp_source_tier_t  best_tier;       /* highest tier this peer claims */
    uint16_t           health_score;
    uint16_t           ec_recv_count;
    uint16_t           ec_drop_count;
    /* rate limiting */
    uint64_t           rate_window_start_ns;
    uint16_t           rate_count;
} edp_peer_t;

/* ── Daemon configuration ──────────────────────────────────────── */
typedef struct edp_config {
    uint32_t  node_id;
    uint8_t   pubkey[EDP_PUBKEY_SIZE];
    uint8_t   privkey[EDP_PRIVKEY_SIZE];
    uint8_t   firmware_hash[EDP_FIRMWARE_HASH_SIZE];
    char      iface[16];            /* network interface, e.g. "eth0" */
    char      multicast_group[64];  /* override default if needed */
    uint16_t  port;                 /* override EDP_UDP_PORT if needed */
    int       ptp_enabled;          /* 1 if PTP is running on this node */
    /*
     * inject_to_kernel()  -- feed mixed entropy into the OS entropy pool.
     * If NULL, EDP writes to /dev/urandom as fallback.
     * Signature: void fn(const uint8_t *bytes, size_t len)
     */
    void (*inject_to_kernel)(const uint8_t *bytes, size_t len);
    /* Optional: called when a peer transitions state */
    void (*on_peer_state_change)(uint32_t node_id, edp_peer_state_t new_state);
    /* Optional: called after each pool mix */
    void (*on_pool_mix)(uint64_t total_mixes, uint64_t pool_entropy_estimate);
} edp_config_t;

/* ── Daemon handle ─────────────────────────────────────────────── */
typedef struct edp_daemon edp_daemon_t;

/* ── Public API ────────────────────────────────────────────────── */

/*
 * edp_daemon_create()  -- Allocate and initialise an EDP daemon.
 * cfg must be fully populated. Returns NULL on error.
 */
edp_daemon_t *edp_daemon_create(const edp_config_t *cfg);

/*
 * edp_daemon_add_source()  -- Register an entropy source.
 * Must be called before edp_daemon_run(). Up to EDP_MAX_SOURCES.
 * Returns 0 on success, -1 if table is full.
 */
int edp_daemon_add_source(edp_daemon_t *d, const edp_source_t *src);

/*
 * edp_daemon_run()  -- Enter the main event loop. Blocks until
 * edp_daemon_stop() is called from a signal handler or another thread.
 */
int edp_daemon_run(edp_daemon_t *d);

/*
 * edp_daemon_stop()  -- Signal the daemon to exit cleanly.
 * Safe to call from a signal handler.
 */
void edp_daemon_stop(edp_daemon_t *d);

/*
 * edp_daemon_destroy()  -- Free all resources.
 * Must be called after edp_daemon_run() returns.
 */
void edp_daemon_destroy(edp_daemon_t *d);

/*
 * edp_generate_identity()  -- Generate a fresh Ed25519 keypair.
 * pub must be EDP_PUBKEY_SIZE bytes, priv EDP_PRIVKEY_SIZE bytes.
 * Uses getrandom() for key material  -- call only after boot entropy
 * is sufficient (i.e., after the kernel pool is initialised).
 */
int edp_generate_identity(uint8_t *pub, uint8_t *priv);

/*
 * edp_get_stats()  -- Snapshot of daemon statistics.
 */
typedef struct {
    uint32_t peers_online;
    uint32_t ec_sent;
    uint32_t ec_recv;
    uint32_t ec_dropped_sig;
    uint32_t ec_dropped_seq;
    uint32_t ec_dropped_rate;
    uint32_t pool_mixes;
    uint64_t bits_harvested;
    uint64_t uptime_ms;
} edp_stats_t;

void edp_get_stats(const edp_daemon_t *d, edp_stats_t *out);
