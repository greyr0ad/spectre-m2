#ifndef VICTIM_PAGE_ORACLE_H
#define VICTIM_PAGE_ORACLE_H

#include <stdint.h>

#define VICTIM_TABLE_ENTRIES 16
#define VICTIM_PUBLIC_SIZE   16

// candidate table pages that the harness probes
extern uint8_t *victim_table[VICTIM_TABLE_ENTRIES];

// init the oracle (allocates internal state)
void victim_oracle_init(void);

// host sets which page the oracle will "secretly select"
void victim_set_oracle_target(int page_idx);

// the only function the attacker can call. bounds-checked access +
// data-dependent __builtin_prefetch on the selected page.
uint8_t victim_oracle_lookup(uint64_t index);

// attacker can read the bound address to flush it (simulates eviction
// set targeting - the attacker knows the library layout)
volatile uint64_t *victim_get_bound_addr(void);

#endif
