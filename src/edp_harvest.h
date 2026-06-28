/*
 * edp_harvest.h — Entropy source implementations
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * Each source implements the edp_source_t.harvest() callback.
 * Platform-specific context is passed via the ctx pointer.
 *
 * Available built-in sources:
 *   edp_src_fpga_trng   — Lattice ECP5 ring-oscillator TRNG via MMIO
 *   edp_src_riscv_seed  — RISC-V Zkt Seed CSR
 *   edp_src_imu         — IMU LSB noise (ICM-42688-P via SPI)
 *   edp_src_encoder     — Motor encoder index pulse timing jitter
 *   edp_src_canfd       — CAN FD inter-frame timing jitter
 *   edp_src_timing      — HAVEGE-style execution timing jitter (fallback)
 *   edp_src_getrandom   — Linux getrandom() (bootstrap/fallback only)
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "../include/edp.h"

/* ── FPGA TRNG source ──────────────────────────────────────────── */

typedef struct {
    volatile uint32_t *data_reg;    /* MMIO: read one 32-bit word of TRNG */
    volatile uint32_t *status_reg;  /* MMIO: bit 0=READY, bit 1=BIST_PASS, bit 2=DEAD */
    volatile uint32_t *fill_reg;    /* MMIO: FIFO fill count in words */
    uint32_t           spin_limit;  /* max iterations waiting for READY */
} edp_fpga_trng_ctx_t;

/*
 * edp_src_fpga_trng_init() — populate an edp_source_t for the FPGA TRNG.
 * base_addr: MMIO base of TRNG peripheral (see trng_top.v register map).
 */
void edp_src_fpga_trng_init(edp_source_t *src, uintptr_t base_addr,
                             edp_fpga_trng_ctx_t *ctx);

int edp_src_fpga_trng_harvest(uint8_t *buf, size_t len, void *ctx);

/* ── RISC-V Seed CSR source (Zkt extension) ────────────────────── */

typedef struct {
    uint32_t max_polls; /* max polls per harvest call */
} edp_seed_csr_ctx_t;

#define SEED_CSR_ES16  0xC0000000u /* status mask: entropy ready */
#define SEED_CSR_BIST  0x80000000u /* self-test mode */
#define SEED_CSR_WAIT  0x40000000u /* not ready */
#define SEED_CSR_DEAD  0x00000000u /* failed */
#define SEED_CSR_MASK  0xC0000000u
#define SEED_CSR_DATA  0x0000FFFFu /* 16 bits of entropy per read */

void edp_src_seed_csr_init(edp_source_t *src, edp_seed_csr_ctx_t *ctx);
int  edp_src_seed_csr_harvest(uint8_t *buf, size_t len, void *ctx);

/* ── IMU LSB noise source (Tier 2) ────────────────────────────── */

typedef struct {
    int   spi_fd;           /* file descriptor for SPI device */
    int   lsb_bits;         /* how many LSBs to extract per axis (typ. 3–4) */
    int   axes;             /* number of axes to sample (typ. 6) */
    int   sample_count;     /* samples to take per harvest call */
} edp_imu_ctx_t;

void edp_src_imu_init(edp_source_t *src, edp_imu_ctx_t *ctx);
int  edp_src_imu_harvest(uint8_t *buf, size_t len, void *ctx);

/* ── Motor encoder timing jitter source (Tier 2) ───────────────── */

typedef struct {
    int      timer_fd;      /* file descriptor for FPGA timer capture */
    uint64_t last_ts;       /* last captured timestamp (ns) */
    uint64_t expected_period_ns; /* nominal period for differencing */
} edp_encoder_ctx_t;

void edp_src_encoder_init(edp_source_t *src, edp_encoder_ctx_t *ctx);
int  edp_src_encoder_harvest(uint8_t *buf, size_t len, void *ctx);

/* ── CAN FD inter-frame timing jitter source (Tier 2) ─────────── */

typedef struct {
    int      sock_fd;       /* CAN socket (raw) */
    uint64_t last_ts_ns;
} edp_canfd_ctx_t;

void edp_src_canfd_init(edp_source_t *src, edp_canfd_ctx_t *ctx);
int  edp_src_canfd_harvest(uint8_t *buf, size_t len, void *ctx);

/* ── HAVEGE-style timing jitter source (Tier 3, fallback) ──────── */

typedef struct {
    uint64_t state[16];     /* walk state */
} edp_timing_ctx_t;

void edp_src_timing_init(edp_source_t *src, edp_timing_ctx_t *ctx);
int  edp_src_timing_harvest(uint8_t *buf, size_t len, void *ctx);

/* ── getrandom() bootstrap source (for testing / fallback) ─────── */
void edp_src_getrandom_init(edp_source_t *src);
int  edp_src_getrandom_harvest(uint8_t *buf, size_t len, void *ctx);
