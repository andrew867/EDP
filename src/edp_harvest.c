/*
 * edp_harvest.c — Entropy source implementations
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#include "edp_harvest.h"
#include "edp_crypto.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/ioctl.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <time.h>
#include <stdio.h>

/* ── Utility: derive per-source conditioning key ───────────────── */
static void derive_source_key(uint8_t key[32], uint32_t node_id,
                               const char *source_name)
{
    uint8_t input[64];
    memset(input, 0, sizeof(input));
    memcpy(input, &node_id, 4);
    size_t nlen = strlen(source_name);
    if (nlen > 28) nlen = 28;
    memcpy(input + 4, source_name, nlen);
    edp_blake3_hash(input, sizeof(input), key);
}

/* ── FPGA TRNG ─────────────────────────────────────────────────── */

void edp_src_fpga_trng_init(edp_source_t *src, uintptr_t base_addr,
                              edp_fpga_trng_ctx_t *ctx)
{
    ctx->data_reg   = (volatile uint32_t *)(base_addr + 0x00);
    ctx->status_reg = (volatile uint32_t *)(base_addr + 0x04);
    ctx->fill_reg   = (volatile uint32_t *)(base_addr + 0x08);
    ctx->spin_limit = 10000;

    memset(src, 0, sizeof(*src));
    strncpy(src->name, "fpga_trng", EDP_SOURCE_NAME_LEN - 1);
    src->tier    = EDP_TIER_FPGA_TRNG;
    src->harvest = edp_src_fpga_trng_harvest;
    src->ctx     = ctx;
    src->health_score = 1000;
    derive_source_key(src->conditioning_key, 0, src->name);
}

int edp_src_fpga_trng_harvest(uint8_t *buf, size_t len, void *vctx)
{
    edp_fpga_trng_ctx_t *ctx = (edp_fpga_trng_ctx_t *)vctx;
    size_t written = 0;

    /* Check BIST status */
    uint32_t status = *ctx->status_reg;
    if (status & 0x4) {
        /* DEAD — TRNG has failed self-test */
        return -1;
    }

    while (written + 4 <= len) {
        uint32_t spin = 0;
        while (!(*ctx->status_reg & 0x1)) { /* wait for READY */
            if (++spin > ctx->spin_limit) return (int)written;
        }
        uint32_t word = *ctx->data_reg;
        memcpy(buf + written, &word, 4);
        written += 4;
    }
    return (int)written;
}

/* ── RISC-V Seed CSR ───────────────────────────────────────────── */

void edp_src_seed_csr_init(edp_source_t *src, edp_seed_csr_ctx_t *ctx)
{
    ctx->max_polls = 2000;
    memset(src, 0, sizeof(*src));
    strncpy(src->name, "riscv_seed_csr", EDP_SOURCE_NAME_LEN - 1);
    src->tier    = EDP_TIER_HW_TRNG;
    src->harvest = edp_src_seed_csr_harvest;
    src->ctx     = ctx;
    src->health_score = 900;
    derive_source_key(src->conditioning_key, 0, src->name);
}

int edp_src_seed_csr_harvest(uint8_t *buf, size_t len, void *vctx)
{
    edp_seed_csr_ctx_t *ctx = (edp_seed_csr_ctx_t *)vctx;
    size_t written = 0;

    while (written + 2 <= len) {
        uint32_t val = 0;
        uint32_t polls = 0;

        /*
         * csrrs a0, seed, x0 — read the Seed CSR.
         * Status is in bits [31:30]; data is in bits [15:0].
         * Encoding: ES16=0b11, BIST=0b10, WAIT=0b01, DEAD=0b00
         *
         * We use inline assembly since there's no standard C intrinsic.
         */
#ifdef __riscv
        do {
            __asm__ volatile ("csrrs %0, seed, x0" : "=r"(val));
            polls++;
        } while ((val & SEED_CSR_MASK) != SEED_CSR_ES16
                 && polls < ctx->max_polls);

        if ((val & SEED_CSR_MASK) == SEED_CSR_DEAD) return -1;
        if ((val & SEED_CSR_MASK) != SEED_CSR_ES16) break;

        uint16_t entropy16 = (uint16_t)(val & SEED_CSR_DATA);
        memcpy(buf + written, &entropy16, 2);
        written += 2;
#else
        /* Non-RISC-V build: fallback to getrandom for testing */
        if (getrandom(buf + written, 2, 0) != 2) return -1;
        written += 2;
        (void)polls; (void)val; (void)ctx;
#endif
    }
    return (int)written;
}

/* ── IMU LSB noise ─────────────────────────────────────────────── */

void edp_src_imu_init(edp_source_t *src, edp_imu_ctx_t *ctx)
{
    memset(src, 0, sizeof(*src));
    strncpy(src->name, "imu_lsb_noise", EDP_SOURCE_NAME_LEN - 1);
    src->tier    = EDP_TIER_SENSOR_PHYSICAL;
    src->harvest = edp_src_imu_harvest;
    src->ctx     = ctx;
    src->health_score = 700;
    derive_source_key(src->conditioning_key, 0, src->name);
}

int edp_src_imu_harvest(uint8_t *buf, size_t len, void *vctx)
{
    edp_imu_ctx_t *ctx = (edp_imu_ctx_t *)vctx;
    /*
     * Read N samples from IMU via SPI. Extract LSB bits from each
     * axis reading. Apply von Neumann corrector, then write to buf.
     *
     * ICM-42688-P register reads: ACCEL_DATA_X1/X0, Y1/Y0, Z1/Z0,
     * GYRO_DATA_X1/X0, Y1/Y0, Z1/Z0 = 12 bytes per sample at 16-bit.
     *
     * For each 16-bit value, take the bottom lsb_bits bits.
     * Pack into byte stream, then apply von Neumann corrector.
     */
    int   samples     = ctx->sample_count;
    int   axes        = ctx->axes;         /* typically 6 */
    int   lsb_bits    = ctx->lsb_bits;     /* typically 3 */
    int   raw_bits    = samples * axes * lsb_bits;
    int   raw_bytes   = (raw_bits + 7) / 8;

    uint8_t raw_buf[256];
    if (raw_bytes > (int)sizeof(raw_buf)) raw_bytes = sizeof(raw_buf);

    /* Read raw IMU data via SPI file descriptor */
    uint8_t spi_rx[12 * 32]; /* up to 32 samples */
    int n_samples = samples;
    if (n_samples > 32) n_samples = 32;

    /*
     * In a real driver this would issue SPI read commands.
     * We read `n_samples * 12` bytes from the SPI fd in one burst.
     */
    ssize_t rd = read(ctx->spi_fd, spi_rx, (size_t)(n_samples * 12));
    if (rd < 12) return 0;
    n_samples = (int)(rd / 12);

    /* Extract LSBs */
    int bit_pos = 0;
    memset(raw_buf, 0, sizeof(raw_buf));
    for (int s = 0; s < n_samples; s++) {
        for (int a = 0; a < axes && a < 6; a++) {
            /* Each axis is 2 bytes (big-endian 16-bit signed) */
            int16_t val;
            memcpy(&val, spi_rx + s*12 + a*2, 2);
            /* Extract lsb_bits least significant bits */
            for (int b = 0; b < lsb_bits; b++) {
                if ((bit_pos / 8) >= (int)sizeof(raw_buf)) goto done;
                int bit = (val >> b) & 1;
                raw_buf[bit_pos / 8] |= (uint8_t)(bit << (bit_pos % 8));
                bit_pos++;
            }
        }
    }
done:;
    /* Von Neumann corrector + conditioning */
    uint8_t vn_buf[128];
    size_t vn_len = edp_von_neumann(raw_buf, (size_t)((bit_pos + 7) / 8),
                                    vn_buf, sizeof(vn_buf));
    if (vn_len == 0) return 0;

    uint8_t conditioned[32];
    edp_blake3_keyed(ctx == vctx ? ((edp_source_t *)vctx - 1)->conditioning_key
                                 : (const uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                     vn_buf, vn_len, conditioned);

    size_t copy = len < 32 ? len : 32;
    memcpy(buf, conditioned, copy);
    return (int)copy;
}

/* ── HAVEGE-style timing jitter (Tier 3 fallback) ──────────────── */

void edp_src_timing_init(edp_source_t *src, edp_timing_ctx_t *ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    /* Seed with current time to differentiate nodes at same boot time */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ctx->state[0] = (uint64_t)ts.tv_nsec ^ (uint64_t)ts.tv_sec;

    memset(src, 0, sizeof(*src));
    strncpy(src->name, "timing_jitter", EDP_SOURCE_NAME_LEN - 1);
    src->tier    = EDP_TIER_TIMING_JITTER;
    src->harvest = edp_src_timing_harvest;
    src->ctx     = ctx;
    src->health_score = 400;
    derive_source_key(src->conditioning_key, 0, src->name);
}

int edp_src_timing_harvest(uint8_t *buf, size_t len, void *vctx)
{
    edp_timing_ctx_t *ctx = (edp_timing_ctx_t *)vctx;
    uint8_t raw[64];
    size_t collected = 0;

    /*
     * HAVEGE-inspired walk: execute a sequence of branches and memory
     * accesses whose timing is sensitive to cache state and pipeline.
     * XOR the cycle counter after each iteration into the output.
     *
     * On RISC-V: rdcycle reads the mcycle CSR.
     * On other platforms: use clock_gettime(CLOCK_MONOTONIC).
     */
    while (collected < sizeof(raw)) {
#ifdef __riscv
        uint64_t cycles;
        __asm__ volatile ("rdcycle %0" : "=r"(cycles));
#else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t cycles = (uint64_t)ts.tv_nsec;
#endif
        /* Mix with walk state */
        ctx->state[collected % 16] ^= cycles;
        ctx->state[(collected + 1) % 16] *= 6364136223846793005ULL;
        ctx->state[(collected + 1) % 16] += 1442695040888963407ULL;

        raw[collected++] = (uint8_t)(ctx->state[collected % 16] >> 32);

        /* Create cache/branch pressure to amplify jitter */
        volatile uint64_t dummy = ctx->state[0] ^ ctx->state[8];
        (void)dummy;
    }

    /* Apply von Neumann + BLAKE3 conditioning */
    uint8_t vn_buf[64];
    size_t vn_len = edp_von_neumann(raw, sizeof(raw), vn_buf, sizeof(vn_buf));
    if (vn_len == 0) {
        /* Worst case: skip von Neumann, just condition */
        vn_len = sizeof(raw);
        memcpy(vn_buf, raw, sizeof(raw));
    }

    uint8_t conditioned[32];
    edp_blake3_hash(vn_buf, vn_len, conditioned); /* no key for fallback */

    size_t copy = len < 32 ? len : 32;
    memcpy(buf, conditioned, copy);
    return (int)copy;
}

/* ── getrandom() fallback ──────────────────────────────────────── */

void edp_src_getrandom_init(edp_source_t *src)
{
    memset(src, 0, sizeof(*src));
    strncpy(src->name, "getrandom_fallback", EDP_SOURCE_NAME_LEN - 1);
    src->tier    = EDP_TIER_TIMING_JITTER; /* conservative tier */
    src->harvest = edp_src_getrandom_harvest;
    src->ctx     = NULL;
    src->health_score = 500;
    derive_source_key(src->conditioning_key, 0, src->name);
}

int edp_src_getrandom_harvest(uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    ssize_t got = getrandom(buf, len, GRND_NONBLOCK);
    if (got < 0) return 0;
    return (int)got;
}
