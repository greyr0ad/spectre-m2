// 256-page flush+reload covert channel on M2.
// architectural touch on arena[secret * PAGE_SIZE] is recovered by probing
// all 256 pages and picking the fastest.
//
// gotchas we hit along the way:
//   - M2 P-cluster shares a 16 MB L2. dc civac from EL0 only flushes L1, so
//     every trial walks a 32 MB scratch to evict L2 before measuring.
//   - sequential mmap() calls pack contiguously ~> region prefetcher pulls
//     neighbouring pages for free. we instead carve scattered probe pages
//     out of a 1 GB arena with >=1 MB gaps.
#include <pthread.h>
#include <pthread/qos.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE_       16384
#define NUM_PAGES        256
#define TRIALS           1000
#define HIT_THRESHOLD    38                   // ticks, below prefetched-miss floor

// arena + scattering params
#define ARENA_PAGES      65536                // 1 GB of VA
#define ARENA_BYTES      ((size_t)ARENA_PAGES * PAGE_SIZE_)
#define MIN_GAP_PAGES    64                   // 1 MB between adjacent picks

// L2 eviction: M2 P-cluster L2 is 16 MB, so 32 MB overwrites it.
#define L2_EVICT_SIZE    (32 * 1024 * 1024)

// counting-thread timer
static volatile uint64_t g_counter = 0;
static volatile int g_run = 1;

static void *counter_thread(void *arg) {
    (void)arg;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    while (g_run) { g_counter++; }
    return NULL;
}

static inline void dc_civac(void *p) { __asm__ volatile("dc civac, %0" :: "r"(p) : "memory"); }
static inline void barrier(void)     { __asm__ volatile("dsb sy\n\tisb" ::: "memory"); }

static inline uint64_t now_ticks(void) {
    __asm__ volatile("dmb ish" ::: "memory");
    return g_counter;
}

static inline uint64_t time_load(volatile uint8_t *p) {
    uint64_t t0, t1; uint8_t v;
    barrier(); t0 = now_ticks(); barrier();
    v = *p; __asm__ volatile("" :: "r"(v) : "memory");
    barrier(); t1 = now_ticks(); barrier();
    return t1 - t0;
}

static void flush_all(uint8_t **pages) {
    for (int i = 0; i < NUM_PAGES; i++) { dc_civac(pages[i]); }
    barrier();
}

// walk >L2 scratch to evict the probe pages out of the shared L2
static void evict_l2(uint8_t *scratch) {
    volatile uint64_t sink = 0;
    for (size_t i = 0; i < L2_EVICT_SIZE; i += 128) { sink ^= scratch[i]; }
    if (sink == 0xdeadbeef) { puts("unreachable"); }
    barrier();
}

static void shuffle(int *order, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = order[i]; order[i] = order[j]; order[j] = t;
    }
}

int main(void) {
    pthread_t tid;
    uint8_t *pages[NUM_PAGES];
    int order[NUM_PAGES];
    int correct = 0, detected = 0, multi_hit = 0;

    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    if (pthread_create(&tid, NULL, counter_thread, NULL) != 0) { perror("pthread_create"); return 1; }
    while (g_counter == 0) { }
    usleep(10000);

    // scatter 256 probe pages across a 1 GB arena ~> region prefetcher can't
    // lock on across MB-scale gaps
    uint8_t *arena = mmap(NULL, ARENA_BYTES, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) { perror("mmap arena"); return 1; }

    srand(1234);
    int slots[NUM_PAGES];
    for (int i = 0; i < NUM_PAGES; i++) {
        slots[i] = i * (ARENA_PAGES / NUM_PAGES) +
                   (rand() % (ARENA_PAGES / NUM_PAGES - MIN_GAP_PAGES));
    }
    for (int i = NUM_PAGES - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = slots[i]; slots[i] = slots[j]; slots[j] = t;
    }
    for (int i = 0; i < NUM_PAGES; i++) {
        pages[i] = arena + (size_t)slots[i] * PAGE_SIZE_;
        pages[i][0] = (uint8_t)i;              // commit page
    }

    for (int i = 0; i < NUM_PAGES; i++) { order[i] = i; }

    uint8_t *l2_scratch = mmap(NULL, L2_EVICT_SIZE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (l2_scratch == MAP_FAILED) { perror("mmap l2_scratch"); return 1; }
    memset(l2_scratch, 1, L2_EVICT_SIZE);

    for (int trial = 0; trial < TRIALS; trial++) {
        int secret = rand() % NUM_PAGES;

        flush_all(pages);
        evict_l2(l2_scratch);

        // arch touch of the secret page
        volatile uint8_t v = *pages[secret]; (void)v;
        barrier();

        shuffle(order, NUM_PAGES);

        // warm timing pipeline on a scratch line outside the arena ~> first
        // time_load in a sweep is ~3x slower otherwise, biases whichever page
        // got probed first
        static uint8_t scratch[256] __attribute__((aligned(128)));
        (void)time_load(scratch);

        int best_page = -1;
        uint64_t best_time = UINT64_MAX;
        int hits_this_trial = 0;
        for (int k = 0; k < NUM_PAGES; k++) {
            int page = order[k];
            uint64_t t = time_load(pages[page]);
            if (t < HIT_THRESHOLD) { hits_this_trial++; }
            if (t < best_time)     { best_time = t; best_page = page; }
        }

        if (hits_this_trial > 0) { detected++; }
        if (hits_this_trial > 1) { multi_hit++; }
        if (best_page == secret) { correct++; }
    }

    printf("trials:           %d\n", TRIALS);
    printf("correct (best):   %d  (%.1f%%)\n", correct,  100.0 * correct  / TRIALS);
    printf("any hit detected: %d  (%.1f%%)\n", detected, 100.0 * detected / TRIALS);
    printf("trials w/ >1 hit: %d  (%.1f%%)\n", multi_hit, 100.0 * multi_hit / TRIALS);
    printf("hit threshold:    %d ticks\n", HIT_THRESHOLD);

    g_run = 0;
    pthread_join(tid, NULL);
    munmap(arena, ARENA_BYTES);
    munmap(l2_scratch, L2_EVICT_SIZE);
    return 0;
}
