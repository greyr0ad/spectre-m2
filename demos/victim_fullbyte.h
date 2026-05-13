#ifndef VICTIM_FULLBYTE_H
#define VICTIM_FULLBYTE_H

#include <stdint.h>

#define VICTIM_V3_TABLE_ENTRIES 16
#define VICTIM_V3_PUBLIC_SIZE   16

extern uint8_t *victim_v3_table_hi[VICTIM_V3_TABLE_ENTRIES];
extern uint8_t *victim_v3_table_lo[VICTIM_V3_TABLE_ENTRIES];

void victim_v3_init(const char *private_key);
void victim_v3_lookup_hi(uint64_t index);
void victim_v3_lookup_lo(uint64_t index);
volatile uint64_t *victim_v3_get_bound_addr(void);
// demo-only: lets the shell driver know expected values for verification
uint8_t victim_v3_get_private_byte(int offset);

#endif
