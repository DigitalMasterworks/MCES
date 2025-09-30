// attacker.c
// Probe MCES walker decisions & optionally histogram them
#include "mces.h"
#include "blake3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

static void u64_to_be(uint64_t x, uint8_t out[8]) {
    for (int i=0;i<8;++i) out[i] = (uint8_t)((x >> (56-8*i)) & 0xFF);
}

// paste these into attacker.c, above main()
static inline void mces_epoch_seed(const MCES_Config *config,
                                   uint64_t epoch,
                                   size_t *current_index,
                                   uint8_t drift_digest[32]) {
    blake3_hasher hh;
    uint8_t epoch_be[8];
    for (int i=0;i<8;++i) epoch_be[i] = (uint8_t)((epoch >> (56-8*i)) & 0xFF);

    uint8_t seed_digest[32];
    blake3_hasher_init(&hh);
    blake3_hasher_update(&hh, config->base_key32, 32);
    blake3_hasher_update(&hh, epoch_be, 8);
    blake3_hasher_finalize(&hh, seed_digest, 32);

    uint64_t start_seed=0;
    for(int i=0;i<8;++i) start_seed=(start_seed<<8)|seed_digest[i];
    *current_index=(size_t)(start_seed % config->count);

    blake3_hasher_init(&hh);
    blake3_hasher_update(&hh,"MCES-drift-v2",13);
    blake3_hasher_update(&hh,config->base_key32,32);
    blake3_hasher_update(&hh,epoch_be,8);
    blake3_hasher_finalize(&hh,drift_digest,32);

    memset(seed_digest,0,32);
}

static inline size_t mces_advance_next_index(const MCES_Config *config,
                                             size_t current_index,
                                             const uint8_t drift_digest[32]) {
    const size_t last_index=config->count-1;
    const uint8_t *h=config->hashes+current_index*32;
    uint64_t h_int=0; for(int i=0;i<8;++i) h_int=(h_int<<8)|h[i];
    int jump=(int)(h_int&1);
    int dir =(int)((h_int>>1)&1);
    uint8_t drift=drift_digest[current_index%32];
    uint64_t off_val=(h_int>>2)^drift;

    size_t next;
    if(jump){
        if(dir==0 && current_index<last_index){
            size_t span=last_index-current_index;
            size_t off=span?(size_t)(off_val%span):0;
            next=current_index+(off?off:1);
        } else if(current_index>0){
            size_t span=current_index;
            size_t off=span?(size_t)(off_val%span):0;
            next=current_index-(off?off:1);
        } else next=current_index+1;
    } else next=(current_index<last_index)?(current_index+1):last_index;
    return next;
}

// Simple config generator (matches mces_stream_dieharder style)
static int make_config(MCES_Config *cfg, uint8_t **postmix, size_t *postmix_len) {
    const char *pw = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; 
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
    uint64_t ts_ns = (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;
    uint8_t nonce[12] = {0};
    FILE *ur = fopen("/dev/urandom","rb");
    if(!ur) return -1;
    fread(nonce,1,12,ur);
    fclose(ur);

    if (generate_config_with_timestamp(pw,NULL,0,ts_ns,cfg)!=0) return -1;

    *postmix_len = 16+32+12+8;
    *postmix = (uint8_t*)malloc(*postmix_len);
    if(!*postmix) return -1;
    memcpy(*postmix,"MCES-POSTMARKER\0",16);
    memcpy(*postmix+16,cfg->base_key32,32);
    memcpy(*postmix+48,nonce,12);
    u64_to_be(ts_ns,*postmix+60);
    return 0;
}

int main(int argc,char**argv){
    int histogram = (argc>1 && strcmp(argv[1],"histo")==0);

    MCES_Config cfg={0};
    uint8_t *postmix=NULL; size_t postmix_len=0;
    if(make_config(&cfg,&postmix,&postmix_len)!=0){
        fprintf(stderr,"[attacker] config gen failed\n");
        return 1;
    }

    size_t length = 1<<20; // 1 MB sample
    uint8_t *ks=(uint8_t*)malloc(length);
    if(!ks) return 1;

    // histo buckets
    unsigned long long jump0=0,jump1=0,dir0=0,dir1=0;
    unsigned long long drift_hist[256]={0};

    uint64_t epoch=0;
    size_t idx=0;
    uint8_t drift_digest[32];
    extern void mces_epoch_seed(const MCES_Config*,uint64_t,size_t*,uint8_t*);
    mces_epoch_seed(&cfg,epoch,&idx,drift_digest);

    for(size_t written=0;written<length;){
        size_t take=32;
        if(written+take>length) take=length-written;
        memcpy(ks+written,cfg.hashes+idx*32,take);
        written+=take;

        const uint8_t *h = cfg.hashes+idx*32;
        uint64_t h_int=0;
        for(int i=0;i<8;++i) h_int=(h_int<<8)|h[i];
        int jump=(int)(h_int&1);
        int dir=(int)((h_int>>1)&1);
        uint8_t drift=drift_digest[idx%32];
        uint64_t offset=(h_int>>2)^drift;

        if(histogram){
            if(jump) jump1++; else jump0++;
            if(jump){ if(dir) dir1++; else dir0++; }
            drift_hist[drift]++;
        } else {
            printf("[leak] idx=%zu jump=%d dir=%d drift=%02x off=%llu\n",
                   idx,jump,dir,drift,(unsigned long long)offset);
        }

        if(idx==cfg.count-1){
            epoch++;
            mces_epoch_seed(&cfg,epoch,&idx,drift_digest);
        } else {
            extern size_t mces_advance_next_index(const MCES_Config*,size_t,const uint8_t[32]);
            idx=mces_advance_next_index(&cfg,idx,drift_digest);
        }
    }

    if(histogram){
        printf("=== Histogram ===\n");
        printf("jump=0: %llu\njump=1: %llu\n",jump0,jump1);
        printf("dir=0 (when jump): %llu\n",dir0);
        printf("dir=1 (when jump): %llu\n",dir1);
        printf("Drift distribution (nonzero counts):\n");
        for(int i=0;i<256;++i){
            if(drift_hist[i]) printf("  drift=%02x : %llu\n",i,drift_hist[i]);
        }
    }

    free(ks); free(postmix); free_config(&cfg);
    return 0;
}