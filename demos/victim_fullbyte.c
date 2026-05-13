// victim_fullbyte.c - separated victim with hi/lo nibble lookup for full-byte
// recovery. one-hop pointer gadget with __builtin_prefetch.
#include "victim_fullbyte.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE 16384

// two pointer arrays: one for hi-nibble lookup, one for lo-nibble.
// in-bounds entries point at D (dummy). OOB entries point at
// table_hi[secret >> 4] or table_lo[secret & 0xf].
static uint64_t ptr_hi[VICTIM_V3_PUBLIC_SIZE + 64] __attribute__((aligned(128)));
static uint64_t ptr_lo[VICTIM_V3_PUBLIC_SIZE + 64] __attribute__((aligned(128)));
static volatile uint64_t *bound_p;
static uint8_t *D_page;
static char private_key_copy[64];
static int key_len;

uint8_t *victim_v3_table_hi[VICTIM_V3_TABLE_ENTRIES];
uint8_t *victim_v3_table_lo[VICTIM_V3_TABLE_ENTRIES];

void victim_v3_init(const char *private_key) {
    key_len = (int)strlen(private_key);
    memcpy(private_key_copy, private_key, key_len);

    D_page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    D_page[0] = 0xFF;

    for (int i = 0; i < VICTIM_V3_TABLE_ENTRIES; i++) {
        victim_v3_table_hi[i] = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        victim_v3_table_hi[i][0] = (uint8_t)i;
        victim_v3_table_lo[i] = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        victim_v3_table_lo[i][0] = (uint8_t)i;
    }

    // in-bounds: point at D
    for (int i = 0; i < VICTIM_V3_PUBLIC_SIZE; i++) {
        ptr_hi[i] = (uint64_t)D_page;
        ptr_lo[i] = (uint64_t)D_page;
    }
    // OOB: point at table page corresponding to each secret byte's nibble
    for (int i = 0; i < key_len; i++) {
        uint8_t byte = (uint8_t)private_key[i];
        ptr_hi[VICTIM_V3_PUBLIC_SIZE + i] = (uint64_t)victim_v3_table_hi[byte >> 4];
        ptr_lo[VICTIM_V3_PUBLIC_SIZE + i] = (uint64_t)victim_v3_table_lo[byte & 0xf];
    }

    bound_p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *bound_p = VICTIM_V3_PUBLIC_SIZE;

}

volatile uint64_t *victim_v3_get_bound_addr(void) { return bound_p; }
uint8_t victim_v3_get_private_byte(int offset) {
    return (uint8_t)private_key_copy[offset];
}

__attribute__((noinline))
void victim_v3_lookup_hi(uint64_t index) {
    if (index < *bound_p) {
        __builtin_prefetch((void *)ptr_hi[index], 0, 3);
    }
}

__attribute__((noinline))
void victim_v3_lookup_lo(uint64_t index) {
    if (index < *bound_p) {
        __builtin_prefetch((void *)ptr_lo[index], 0, 3);
    }
}
