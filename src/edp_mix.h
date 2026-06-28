/*
 * edp_mix.h — Entropy pool management and mixing
 * Hydrogenuine / Project DOCS
 * MIT License
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "edp_types.h"
#include "../vendor/blake3.h"

void edp_staging_init(edp_staging_t *s);
void edp_staging_push(edp_staging_t *s, const uint8_t *data, size_t len);
size_t edp_staging_drain(edp_staging_t *s, uint8_t *out, size_t want);

void edp_pool_init(edp_pool_t *pool, const uint8_t *seed, size_t seed_len);
void edp_pool_mix_local(edp_pool_t *pool, const uint8_t *data, size_t len,
                         uint8_t source_tier);
void edp_pool_mix_remote(edp_pool_t *pool,
                          const uint8_t *ec_entropy, size_t ec_len,
                          const uint8_t *source_metadata, size_t meta_len,
                          uint8_t peer_tier);
void edp_pool_extract(edp_pool_t *pool, uint8_t *out, size_t len);
void edp_pool_inject_to_kernel(edp_pool_t *pool,
                                void (*injector)(const uint8_t *, size_t));
