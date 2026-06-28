/*
 * bench.c — EDP performance benchmarks (stub)
 * Hydrogenuine / Project DOCS
 * MIT License
 *
 * NOTE: This is a placeholder. Actual benchmark implementation is planned
 * for a future release. The bench target currently measures BLAKE3 and
 * pool-mix throughput on the host platform.
 *
 * To run once implemented:
 *   cmake -B build -DCMAKE_BUILD_TYPE=Release
 *   cmake --build build --target bench
 *   ./build/bench
 */
#include <stdio.h>
int main(void) {
    printf("EDP benchmark stub — not yet implemented.\n");
    printf("See docs/protocol_limitations.md for planned performance targets.\n");
    return 0;
}
