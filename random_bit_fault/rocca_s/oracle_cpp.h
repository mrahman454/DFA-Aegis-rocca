/* gist: This is c code for rocca-s. Four test vectors (link: https://www.ietf.org/id/draft-nakano-rocca-s-03.html) */
/* have passed. The problem lies in padding. If the ad len or msg len is not multiple of 256, then the number of zeros it */ 
/* has to padd, it cannot detect that. O.w. if the lengths are multiple of 256, then the code runs properly. */
/* ----------------------------------------------------------------------------------------------- */

/* applying one aes round functions on x and return by xoring the resultant with y */
void aes(uint64_t *x, uint64_t *y){
    sbox(x);
    sr(x);
    mc(x);
    xr(x, y, 128);
    }


/* applying one aes round functions on x */
void a(uint64_t *x){
    sbox(x);
    sr(x);
    mc(x);
    }


/* changing the msb and lsb ordering according to the byte */
void byte_rev(uint64_t *msg, uint64_t size){
    uint64_t *new_msg = mem_alloc(size);

    /* for each 64-bit bytes */
    for (uint32_t i=0; i<(size/64); i++){
        uint64_t cip = 0UL;

        /* for each byte in 64-bit */
        for (int8_t byte=0; byte<8; byte++){
            cip = (cip<<8) | (msg[i] >> 8*byte)&0xff;
            }
        new_msg[size/64 - 1 - i] = cip;
        }

    copy(msg, new_msg, (uint32_t)size);
    free(new_msg);
    }



/* defining R function */
void R(uint64_t *state, uint64_t *x0, uint64_t *x1){
    /* new state forwarded in the next round */  
    uint64_t *new_state = mem_alloc(7*128);

    /* s_new[0] = s[6]^s[1] */
    copy(&new_state[0], &state[12], (uint32_t)128);   xr(&new_state[0], &state[2], 128);

    /* s_new[1] = aes(s[0], x0) */
    copy(&new_state[2], &state[0], (uint32_t)128);    aes(&new_state[2], x0);

    /* s_new[2] = aes(s[1], s[0]) */
    copy(&new_state[4], &state[2], (uint32_t)128);    aes(&new_state[4], &state[0]);

    /* s_new[3] = aes(s[2], s[6]) */
    copy(&new_state[6], &state[4], (uint32_t)128);    aes(&new_state[6], &state[12]);

    /* s_new[4] = aes(s[3], x1) */
    copy(&new_state[8], &state[6], (uint32_t)128);    aes(&new_state[8], x1);

    /* s_new[5] = aes(s[4], s[3]) */
    copy(&new_state[10], &state[8], (uint32_t)128);   aes(&new_state[10], &state[6]);

    /* s_new[6] = aes(s[5], s[4]) */
    copy(&new_state[12], &state[10], (uint32_t)128);  aes(&new_state[12], &state[8]);
    
    copy(state, new_state, (uint32_t)7*128);
    free(new_state);
    }


void initialization(uint64_t *state, uint64_t *nonce, uint64_t *k0, uint64_t *k1){
    /* defining constant blocks z0 and z1 */
    uint64_t *z0 = mem_alloc(128);
    uint64_t *z1 = mem_alloc(128);

    /* inserting constant blocks z0 and z1. In the paper, the lsB (byte) is the left most one. But according */
    /* to our convention, its the left most one. So, the constants are modified accordingly. */
    insert(z0, 0xcd65ef2391443771, 0x22ae28d7982f8a42);
    insert(z1, 0xbcdb8981a5dbb5e9, 0x2f3b4deccffbc0b5);

    /* initializing state from given keys and nonce */
    copy(&state[0], k1, (uint32_t)128);
    copy(&state[2], nonce, (uint32_t)128);
    copy(&state[4], z0, (uint32_t)128);
    copy(&state[6], k0, (uint32_t)128);

    copy(&state[8], z1, (uint32_t)128);
    copy(&state[10], nonce, (uint32_t)128);    xr(&state[10], k1, 128);
    insert(&state[12], 0x0UL, 0x0UL);

    /* applying round functions */
    for (uint8_t i=0; i<16; i++){
        R(state, z0, z1); 
        }

    /* post initialization process */
    xr(&state[0], k0, 128);
    xr(&state[2], k0, 128);
    xr(&state[4], k1, 128);
    xr(&state[6], k0, 128);
    xr(&state[8], k0, 128);
    xr(&state[10], k1, 128);
    xr(&state[12], k1, 128);
    }


/* processing associate data */
void process_ad(uint64_t *state, uint64_t *ad, uint64_t ad_len_bar){
    uint32_t d = ad_len_bar/256;

    for (uint32_t i=0; i<d; i++){
        R(state, &ad[4*i], &ad[4*i + 2]);
        }}


/* encryption function */
void enc(uint64_t *state, uint64_t *msg, uint64_t *cip){
    uint32_t m = msg_len/256;

    for (uint32_t i=0; i<m; i++){
        copy(&cip[4*i], &state[6], (uint32_t)128);   xr(&cip[4*i], &state[10], 128);  aes(&cip[4*i], &state[0]);
        xr(&cip[4*i], &msg[4*i], 128);

        copy(&cip[4*i + 2], &state[8], (uint32_t)128);    xr(&cip[4*i + 2], &state[12], 128);  aes(&cip[4*i + 2], &state[4]);
        xr(&cip[4*i + 2], &msg[4*i + 2], 128);

        R(state, &msg[4*i], &msg[4*i + 2]);
        }}


void finalization(uint64_t *state, uint64_t *t, uint64_t *ad_len_state, uint64_t *msg_len_state){
    for (uint8_t i=0; i<16; i++){
        R(state, ad_len_state, msg_len_state);
        }

    /* initializing tag with zero state */
    insert(&t[0], 0x0UL, 0x0UL);    insert(&t[2], 0x0UL, 0x0UL);

    /* making 256-bit tag */
    for (uint8_t i=0; i<4; i++){
        xr(&t[0], &state[2*i], 128);
    }

    for (uint8_t i=4; i<7; i++){
        xr(&t[2], &state[2*i], 128);
    }
}


void padd(uint64_t *msg, uint32_t zero_len, uint32_t size){
    /* define left shift */
    shift(msg, zero_len, size, LEFT);
    }


void rocca_s_enc( uint64_t *state, uint64_t *cip, uint64_t *tag, uint64_t *k0, uint64_t *k1, uint64_t *nonce, 
                uint64_t *ad, uint64_t *msg, uint32_t ad_len_bar, uint32_t msg_len_bar){
    /* initialization */
    initialization(state, nonce, k0, k1);

    /* processing associate data */
    if (ad_len > 0){
        /* /1* if the ad len is not a multiple of 256, then paddd 0's in the last *1/ */
        /* if (ad_len != ad_len_bar){ */
        /*     uint16_t last128 = 64*(ad_len/64); */
        /*     padd(&ad[ad_len/128 + 1], 128 - (ad_len%128), 128); */
        /*     } */

        process_ad(state, ad, ad_len_bar);
        }

    /* encryption process of the msg */
    if (msg_len > 0){
        /* /1* if the msg len is not a multiple of 256, then paddd 0's in the last *1/ */
        /* if (msg_len != msg_len_bar){ */
        /*     padd(msg, 128 - msg_len%128, msg_len_bar); */
        /*     } */

        enc(state, msg, cip);
        }


    uint64_t *ad_len_state = mem_alloc(128);
    uint64_t *msg_len_state = mem_alloc(128);

    /* inserting ad len and msg len according to lsB on left */
    insert(ad_len_state, 0x0, ad_len);      byte_rev(ad_len_state, 128);
    insert(msg_len_state, 0x0, msg_len);    byte_rev(msg_len_state, 128);

    /* finalization process */
    finalization(state, tag, ad_len_state, msg_len_state);
    }


/* uint32_t find_bar_size(uint32_t size){ */
/*     uint32_t bar_size = 0; */

/*     if ((size%128) == 0){ */
/*         bar_size = size; */
/*         } */
/*     else{ */
/*         bar_size = 128*(size/128 + 1); */
/*         } */
/*     return bar_size; */
/*     } */



