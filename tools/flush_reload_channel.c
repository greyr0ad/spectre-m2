// flush+reload baseline on M2. verifies dc civac actually flushes and the
// counting-thread timer can tell an L1 hit apart from a DRAM miss.
#include <pthread.h>
#include <pthread/qos.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CACHE_LINE 128
#define BUF_SIZE   4096

// mach_absolute_time ticks at 24 MHz (~42 ns). too coarse to tell L1 (~1 ns)
// from DRAM (~80 ns). sibling thread spins on g_counter++ ~> sub-ns resolution.
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
    v = *p;
    __asm__ volatile("" :: "r"(v) : "memory");
    barrier(); t1 = now_ticks(); barrier();
    return t1 - t0;
}

int main(void) {
    pthread_t tid;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    if (pthread_create(&tid, NULL, counter_thread, NULL) != 0) { perror("pthread_create"); return 1; }
    while (g_counter == 0) { }
    usleep(10000);

    uint8_t *buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }
    memset(buf, 0xAB, BUF_SIZE);

    volatile uint8_t *target = buf + 2 * CACHE_LINE;

    // flush, load (warm), flush again
    dc_civac((void *)target); barrier();
    (void)*target;            barrier();
    dc_civac((void *)target); barrier();

    // time a flushed load ~> expect miss
    uint64_t miss_t = time_load(target);

    // warm, then time ~> expect hit
    (void)*target; barrier();
    uint64_t hit_t = time_load(target);

    printf("buffer: %p   target line: %p\n", (void *)buf, (void *)target);
    printf("counter ticks during 10 ms warmup: %llu\n", (unsigned long long)g_counter);
    printf("miss (after dc civac): %6llu ticks\n", (unsigned long long)miss_t);
    printf("hit  (warm cache):     %6llu ticks\n", (unsigned long long)hit_t);

    g_run = 0;
    pthread_join(tid, NULL);
    munmap(buf, BUF_SIZE);
    return 0;
}
