// victim_page_oracle.c - one-hop oracle, simple separate mmaps.
#include "victim_page_oracle.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE 16384

static uint64_t ptr_array[VICTIM_PUBLIC_SIZE + 4]
    __attribute__((aligned(128)));
static volatile uint64_t *bound_p;
static uint8_t *D_page;

uint8_t *victim_table[VICTIM_TABLE_ENTRIES];

void victim_oracle_init(void) {
    D_page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    D_page[0] = 0xFF;
    for (int i = 0; i < VICTIM_TABLE_ENTRIES; i++) {
        victim_table[i] = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        victim_table[i][0] = (uint8_t)i;
    }
    for (int i = 0; i < VICTIM_PUBLIC_SIZE; i++)
        ptr_array[i] = (uint64_t)D_page;
    ptr_array[VICTIM_PUBLIC_SIZE] = (uint64_t)D_page;
    bound_p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *bound_p = VICTIM_PUBLIC_SIZE;
}

void victim_set_oracle_target(int page_idx) {
    ptr_array[VICTIM_PUBLIC_SIZE] = (uint64_t)victim_table[page_idx];
}

volatile uint64_t *victim_get_bound_addr(void) {
    return bound_p;
}

__attribute__((noinline))
uint8_t victim_oracle_lookup(uint64_t index) {
    if (index < *bound_p) {
        uint8_t *p = (uint8_t *)ptr_array[index];
        __builtin_prefetch(p, 0, 3);
        return p[0];
    }
    return 0;
}
