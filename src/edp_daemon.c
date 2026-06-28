/*
 * edp_daemon.c  -- Main EDP daemon: event loop, timers, recv dispatch
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Architecture: single-threaded event loop with timerfd + epoll.
 * All state is in the edp_daemon_t struct (no globals).
 * Signal-safe stop via a pipe (POSIX self-pipe trick).
 */
#include "../include/edp.h"
#include "edp_types.h"
#include "edp_crypto.h"
#include "edp_harvest.h"
#include "edp_mix.h"
#include "edp_protocol.h"
#include "edp_peer.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <sys/random.h>

#define MAX_PKT_SIZE   512
#define MAX_EVENTS     8

struct edp_daemon {
    edp_config_t      cfg;

    /* Entropy state */
    edp_source_t      sources[EDP_MAX_SOURCES];
    int               nsources;
    edp_staging_t     staging;
    edp_pool_t        pool;
    uint32_t          tx_sequence;

    /* Peer management */
    edp_peer_table_t  peers;

    /* Networking */
    int               sock_fd;     /* UDP multicast socket */
    struct sockaddr_in mcast_addr; /* destination for sends */

    /* Event loop */
    int               epoll_fd;
    int               timer_harvest_fd;
    int               timer_broadcast_fd;
    int               timer_hello_fd;
    int               timer_tick_fd;  /* periodic peer timeout check */
    int               stop_pipe[2];   /* self-pipe for clean shutdown */
    volatile int      running;

    /* Statistics */
    edp_stats_t       stats;
    uint64_t          start_ns;
};

/* ── Forward declarations ──────────────────────────────────────── */
static int  setup_socket(edp_daemon_t *d);
static int  setup_timers(edp_daemon_t *d);
static void handle_harvest(edp_daemon_t *d);
static void handle_broadcast(edp_daemon_t *d);
static void handle_hello(edp_daemon_t *d);
static void handle_tick(edp_daemon_t *d);
static void handle_recv(edp_daemon_t *d);
static void dispatch_hello(edp_daemon_t *d, const uint8_t *buf, size_t len,
                            const struct sockaddr_in *from);
static void dispatch_ec(edp_daemon_t *d, const uint8_t *buf, size_t len,
                         const struct sockaddr_in *from);
static void dispatch_revoke(edp_daemon_t *d, const uint8_t *buf, size_t len);
static int  arm_timerfd(int fd, uint64_t first_ms, uint64_t period_ms);
static void drain_timerfd(int fd);
static uint64_t monotonic_ns(void);

/* ── Public API ────────────────────────────────────────────────── */

edp_daemon_t *edp_daemon_create(const edp_config_t *cfg)
{
    edp_daemon_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;

    memcpy(&d->cfg, cfg, sizeof(*cfg));
    edp_staging_init(&d->staging);
    edp_pool_init(&d->pool, NULL, 0); /* bootstrap from getrandom */
    edp_peer_table_init(&d->peers);
    d->peers.on_state_change = cfg->on_peer_state_change;
    d->running   = 0;
    d->start_ns  = monotonic_ns();
    return d;
}

int edp_daemon_add_source(edp_daemon_t *d, const edp_source_t *src)
{
    if (d->nsources >= EDP_MAX_SOURCES) return -1;
    memcpy(&d->sources[d->nsources++], src, sizeof(*src));
    return 0;
}

int edp_daemon_run(edp_daemon_t *d)
{
    if (pipe(d->stop_pipe) < 0) return -1;

    d->epoll_fd = epoll_create1(0);
    if (d->epoll_fd < 0) return -1;

    if (setup_socket(d) < 0) return -1;
    if (setup_timers(d) < 0) return -1;

    /* Register all fds with epoll */
    struct epoll_event ev = { .events = EPOLLIN };
    int fds[] = { d->sock_fd, d->timer_harvest_fd, d->timer_broadcast_fd,
                  d->timer_hello_fd, d->timer_tick_fd, d->stop_pipe[0] };
    for (size_t i = 0; i < sizeof(fds)/sizeof(fds[0]); i++) {
        ev.data.fd = fds[i];
        epoll_ctl(d->epoll_fd, EPOLL_CTL_ADD, fds[i], &ev);
    }

    d->running = 1;

    /* Send initial HELLO */
    handle_hello(d);

    struct epoll_event events[MAX_EVENTS];
    while (d->running) {
        int n = epoll_wait(d->epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            if (fd == d->stop_pipe[0]) {
                d->running = 0;
                break;
            } else if (fd == d->timer_harvest_fd) {
                drain_timerfd(fd);
                handle_harvest(d);
            } else if (fd == d->timer_broadcast_fd) {
                drain_timerfd(fd);
                handle_broadcast(d);
            } else if (fd == d->timer_hello_fd) {
                drain_timerfd(fd);
                handle_hello(d);
            } else if (fd == d->timer_tick_fd) {
                drain_timerfd(fd);
                handle_tick(d);
            } else if (fd == d->sock_fd) {
                handle_recv(d);
            }
        }
    }

    close(d->epoll_fd);
    close(d->sock_fd);
    close(d->timer_harvest_fd);
    close(d->timer_broadcast_fd);
    close(d->timer_hello_fd);
    close(d->timer_tick_fd);
    close(d->stop_pipe[0]);
    close(d->stop_pipe[1]);
    return 0;
}

void edp_daemon_stop(edp_daemon_t *d)
{
    /* Safe to call from signal handler: write to pipe triggers epoll */
    uint8_t b = 1;
    write(d->stop_pipe[1], &b, 1);
}

void edp_daemon_destroy(edp_daemon_t *d)
{
    if (!d) return;
    edp_wipe(d->cfg.privkey, EDP_PRIVKEY_SIZE);
    edp_wipe(d->pool.state, sizeof(d->pool.state));
    free(d);
}

void edp_get_stats(const edp_daemon_t *d, edp_stats_t *out)
{
    memcpy(out, &d->stats, sizeof(*out));
    out->peers_online = edp_peer_count_online(&d->peers);
    out->uptime_ms    = (monotonic_ns() - d->start_ns) / 1000000ULL;
}

int edp_generate_identity(uint8_t *pub, uint8_t *priv)
{
    uint8_t seed[32];
    if (getrandom(seed, sizeof(seed), 0) != (ssize_t)sizeof(seed)) return -1;
    edp_ed25519_keygen(seed, pub, priv);
    edp_wipe(seed, sizeof(seed));
    return 0;
}

/* ── Harvest timer handler ─────────────────────────────────────── */

static void handle_harvest(edp_daemon_t *d)
{
    uint8_t raw[64];
    for (int i = 0; i < d->nsources; i++) {
        edp_source_t *src = &d->sources[i];
        int got = src->harvest(raw, sizeof(raw), src->ctx);
        if (got <= 0) {
            src->health_score = (uint16_t)(src->health_score * 9 / 10);
            continue;
        }
        /* Condition through source's BLAKE3 key */
        uint8_t conditioned[32];
        edp_blake3_keyed(src->conditioning_key, raw, (size_t)got, conditioned);

        /* Push to staging buffer */
        edp_staging_push(&d->staging, conditioned, sizeof(conditioned));

        /* Mix directly into local pool */
        edp_pool_mix_local(&d->pool, conditioned, sizeof(conditioned), src->tier);

        src->bits_total += (uint64_t)got * 8;
        d->stats.bits_harvested += (uint64_t)got * 8;

        /* Recover health score */
        if (src->health_score < 1000) src->health_score += 10;
        if (src->health_score > 1000) src->health_score = 1000;
    }
    edp_wipe(raw, sizeof(raw));

    /* Inject mixed entropy into kernel pool every harvest cycle */
    edp_pool_inject_to_kernel(&d->pool, d->cfg.inject_to_kernel);
}

/* ── Broadcast timer handler ───────────────────────────────────── */

static void handle_broadcast(edp_daemon_t *d)
{
    uint8_t entropy[EDP_EC_ENTROPY_BYTES];
    size_t drained = edp_staging_drain(&d->staging, entropy, sizeof(entropy));
    if (drained == 0) {
        /* Nothing staged yet; derive from pool directly */
        edp_pool_extract(&d->pool, entropy, sizeof(entropy));
        drained = sizeof(entropy);
    } else if (drained < sizeof(entropy)) {
        /* Pad with pool-derived bytes */
        uint8_t pad[EDP_EC_ENTROPY_BYTES];
        edp_pool_extract(&d->pool, pad, sizeof(pad));
        memcpy(entropy + drained, pad, sizeof(entropy) - drained);
        edp_wipe(pad, sizeof(pad));
    }

    /* Pick best source tier from available sources */
    edp_source_tier_t best_tier = EDP_TIER_TIMING_JITTER;
    uint16_t best_health = 0;
    for (int i = 0; i < d->nsources; i++) {
        if ((int)d->sources[i].tier < (int)best_tier) {
            best_tier = d->sources[i].tier;
        }
        if (d->sources[i].health_score > best_health)
            best_health = d->sources[i].health_score;
    }

    edp_pkt_ec_t pkt;
    edp_build_ec(&pkt,
                 d->cfg.node_id,
                 ++d->tx_sequence,
                 best_tier,
                 best_health,
                 entropy,
                 d->cfg.privkey,
                 d->cfg.ptp_enabled);

    sendto(d->sock_fd, &pkt, sizeof(pkt), 0,
           (struct sockaddr *)&d->mcast_addr, sizeof(d->mcast_addr));
    d->stats.ec_sent++;
    edp_wipe(entropy, sizeof(entropy));
}

/* ── Hello timer handler ───────────────────────────────────────── */

static void handle_hello(edp_daemon_t *d)
{
    /* Build source_tiers_bitmap and capabilities from registered sources */
    uint8_t bitmap = 0;
    uint16_t caps  = 0;
    for (int i = 0; i < d->nsources; i++) {
        bitmap |= (uint8_t)(1 << d->sources[i].tier);
        if (d->sources[i].tier == EDP_TIER_FPGA_TRNG) caps |= EDP_CAP_FPGA_TRNG;
        if (d->sources[i].tier == EDP_TIER_HW_TRNG)   caps |= EDP_CAP_RISCV_SEED_CSR;
        if (d->sources[i].tier == EDP_TIER_SENSOR_PHYSICAL) caps |= EDP_CAP_SENSOR_ARRAY;
    }
    if (d->cfg.ptp_enabled) caps |= EDP_CAP_PTP_CAPABLE;

    edp_pkt_hello_t pkt;
    edp_build_hello(&pkt,
                    d->cfg.node_id,
                    d->cfg.pubkey,
                    d->cfg.privkey,
                    bitmap,
                    caps,
                    (uint8_t)d->nsources,
                    d->cfg.firmware_hash);

    sendto(d->sock_fd, &pkt, sizeof(pkt), 0,
           (struct sockaddr *)&d->mcast_addr, sizeof(d->mcast_addr));
}

/* ── Tick handler (peer timeout check) ────────────────────────── */

static void handle_tick(edp_daemon_t *d)
{
    edp_peer_tick(&d->peers, NULL /* no extra callback for now */);
}

/* ── Receive handler ───────────────────────────────────────────── */

static void handle_recv(edp_daemon_t *d)
{
    uint8_t buf[MAX_PKT_SIZE];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    ssize_t len = recvfrom(d->sock_fd, buf, sizeof(buf), 0,
                            (struct sockaddr *)&from, &fromlen);
    if (len < 4) return;

    /* Ignore our own packets */
    uint32_t sender_id;
    memcpy(&sender_id, buf + 4, 4);
    sender_id = ntohl(sender_id);
    if (sender_id == d->cfg.node_id) return;

    uint8_t pkt_type = EDP_HDR_TYPE(buf[0]);

    switch (pkt_type) {
    case EDP_PKT_HELLO:  dispatch_hello(d, buf, (size_t)len, &from);  break;
    case EDP_PKT_EC:     dispatch_ec(d, buf, (size_t)len, &from);     break;
    case EDP_PKT_REVOKE: dispatch_revoke(d, buf, (size_t)len);        break;
    default: break; /* Unknown packet type: ignore */
    }
}

static void dispatch_hello(edp_daemon_t *d, const uint8_t *buf, size_t len,
                             const struct sockaddr_in *from)
{
    edp_pkt_hello_t hello;
    if (edp_parse_hello(buf, len, &hello) < 0) return;

    /* For a brand-new peer, we must verify with the pubkey from the packet */
    if (edp_verify_hello_raw(buf, len, hello.pubkey) < 0) return;

    edp_peer_t *peer = edp_peer_upsert_hello(&d->peers, &hello);
    if (!peer) return; /* Table full */

    /* Store the peer's address for any future unicast needs */
    (void)from; /* Currently using multicast for all TX */
}

static void dispatch_ec(edp_daemon_t *d, const uint8_t *buf, size_t len,
                          const struct sockaddr_in *from)
{
    (void)from;

    /* Parse first to get node_id */
    edp_pkt_ec_t ec;
    if (edp_parse_ec(buf, len, &ec) < 0) return;

    edp_peer_t *peer = edp_peer_find(&d->peers, ec.node_id);

    /* Peer checks before expensive signature verification */
    edp_peer_ec_result_t result = edp_peer_check_ec(&d->peers, peer, &ec);
    if (result != EDP_PEER_ACCEPT) {
        switch (result) {
        case EDP_PEER_DROP_REPLAY: d->stats.ec_dropped_seq++; break;
        case EDP_PEER_DROP_RATE:   d->stats.ec_dropped_rate++; break;
        default:                   d->stats.ec_dropped_sig++; break;
        }
        edp_peer_record_drop(peer);
        return;
    }

    /* Now verify signature (expensive: ~8ms on RV32 E-core) */
    if (edp_verify_ec_raw(buf, len, peer->pubkey) < 0) {
        d->stats.ec_dropped_sig++;
        edp_peer_record_drop(peer);
        return;
    }

    /* Accept: mix into pool */
    uint8_t meta[8];
    uint32_t nid_be = htonl(ec.node_id);
    memcpy(meta, &nid_be, 4);
    meta[4] = ec.source_tier;
    meta[5] = (uint8_t)(ec.health_score >> 8);
    meta[6] = (uint8_t)(ec.health_score & 0xFF);
    meta[7] = 0;

    edp_pool_mix_remote(&d->pool,
                         ec.entropy, ec.entropy_byte_count,
                         meta, sizeof(meta),
                         ec.source_tier);

    /* Inject result into kernel */
    edp_pool_inject_to_kernel(&d->pool, d->cfg.inject_to_kernel);

    edp_peer_record_ec(peer, &ec);
    d->stats.ec_recv++;
    d->stats.pool_mixes++;

    if (d->cfg.on_pool_mix)
        d->cfg.on_pool_mix(d->stats.pool_mixes, d->pool.entropy_estimate);
}

static void dispatch_revoke(edp_daemon_t *d, const uint8_t *buf, size_t len)
{
    if (len < sizeof(edp_pkt_revoke_t)) return;

    edp_pkt_revoke_t rev;
    memcpy(&rev, buf, sizeof(rev));
    uint32_t node_id = ntohl(rev.node_id);

    edp_peer_t *peer = edp_peer_find(&d->peers, node_id);
    if (!peer) return;

    /* Verify revoke is signed with the known key */
    if (edp_ed25519_verify(peer->pubkey, buf,
                            sizeof(rev) - EDP_SIG_SIZE,
                            rev.signature) < 0) return;

    edp_peer_revoke(&d->peers, node_id);
}

/* ── Networking setup ──────────────────────────────────────────── */

static int setup_socket(edp_daemon_t *d)
{
    const char *group = d->cfg.multicast_group[0] ?
                        d->cfg.multicast_group : EDP_MULTICAST_GROUP;
    uint16_t port = d->cfg.port ? d->cfg.port : EDP_UDP_PORT;

    d->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (d->sock_fd < 0) return -1;

    int yes = 1;
    setsockopt(d->sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(d->sock_fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));

    /* Bind to multicast port */
    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = { .s_addr = htonl(INADDR_ANY) }
    };
    if (bind(d->sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0)
        return -1;

    /* Join multicast group on the configured interface */
    struct ip_mreqn mreq = {0};
    inet_pton(AF_INET, group, &mreq.imr_multiaddr);
    mreq.imr_ifindex = (int)if_nametoindex(d->cfg.iface[0] ? d->cfg.iface : "eth0");
    setsockopt(d->sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* Set TTL for multicast */
    uint8_t ttl = EDP_MULTICAST_TTL;
    setsockopt(d->sock_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    /* Disable multicast loopback (don't recv our own packets) */
    uint8_t loop = 0;
    setsockopt(d->sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

    /* Destination address for sends */
    memset(&d->mcast_addr, 0, sizeof(d->mcast_addr));
    d->mcast_addr.sin_family = AF_INET;
    d->mcast_addr.sin_port   = htons(port);
    inet_pton(AF_INET, group, &d->mcast_addr.sin_addr);

    return 0;
}

/* ── Timer helpers ─────────────────────────────────────────────── */

static int setup_timers(edp_daemon_t *d)
{
    d->timer_harvest_fd   = timerfd_create(CLOCK_MONOTONIC, 0);
    d->timer_broadcast_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    d->timer_hello_fd     = timerfd_create(CLOCK_MONOTONIC, 0);
    d->timer_tick_fd      = timerfd_create(CLOCK_MONOTONIC, 0);

    if (d->timer_harvest_fd   < 0 || d->timer_broadcast_fd < 0 ||
        d->timer_hello_fd     < 0 || d->timer_tick_fd      < 0) return -1;

    arm_timerfd(d->timer_harvest_fd,   EDP_HARVEST_INTERVAL_MS,  EDP_HARVEST_INTERVAL_MS);
    arm_timerfd(d->timer_broadcast_fd, EDP_BROADCAST_INTERVAL_MS,EDP_BROADCAST_INTERVAL_MS);
    arm_timerfd(d->timer_hello_fd,     500,                       EDP_HELLO_INTERVAL_MS);
    arm_timerfd(d->timer_tick_fd,      1000,                      1000);
    return 0;
}

static int arm_timerfd(int fd, uint64_t first_ms, uint64_t period_ms)
{
    struct itimerspec its = {
        .it_value    = { .tv_sec = first_ms  / 1000,
                         .tv_nsec = (long)((first_ms  % 1000) * 1000000L) },
        .it_interval = { .tv_sec = period_ms / 1000,
                         .tv_nsec = (long)((period_ms % 1000) * 1000000L) }
    };
    return timerfd_settime(fd, 0, &its, NULL);
}

static void drain_timerfd(int fd)
{
    uint64_t exp;
    read(fd, &exp, sizeof(exp));
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* -- Main entry point ------------------------------------------------- */

static edp_daemon_t *g_daemon = NULL;

static void sighandler(int sig)
{
    (void)sig;
    if (g_daemon) edp_daemon_stop(g_daemon);
}

static int getrandom_harvest(uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    ssize_t got = getrandom(buf, len, 0);
    return (got > 0) ? (int)got : -1;
}

int main(int argc, char **argv)
{
    edp_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.port = EDP_UDP_PORT;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            cfg.port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc)
            strncpy(cfg.iface, argv[++i], sizeof(cfg.iface) - 1);
    }

    if (edp_generate_identity(cfg.pubkey, cfg.privkey) < 0) {
        fprintf(stderr, "edpd: failed to generate identity\n");
        return 1;
    }
    cfg.node_id = (uint32_t)((uint32_t)cfg.pubkey[0] << 24 |
                             (uint32_t)cfg.pubkey[1] << 16 |
                             (uint32_t)cfg.pubkey[2] << 8  |
                             (uint32_t)cfg.pubkey[3]);

    g_daemon = edp_daemon_create(&cfg);
    if (!g_daemon) {
        fprintf(stderr, "edpd: failed to create daemon\n");
        return 1;
    }

    edp_source_t src;
    memset(&src, 0, sizeof(src));
    strncpy(src.name, "getrandom", EDP_SOURCE_NAME_LEN - 1);
    src.tier = EDP_TIER_TIMING_JITTER;
    src.harvest = getrandom_harvest;
    src.health_score = 500;
    edp_blake3_hash((const uint8_t *)"edp-getrandom-key", 17,
                    src.conditioning_key);
    edp_daemon_add_source(g_daemon, &src);

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    printf("edpd: starting (node %08x, port %u)\n", cfg.node_id, cfg.port);
    int rc = edp_daemon_run(g_daemon);
    edp_daemon_destroy(g_daemon);
    return rc;
}
