

/* encryption function */
void fenc(uint64_t *state, uint64_t *msg, uint64_t *cip, uint64_t *fval){
    uint32_t m = msg_len/256;

    for (uint32_t i=0; i<m; i++){
        copy(&cip[4*i], &state[6], (uint32_t)128);   xr(&cip[4*i], &state[10], 128);  

        /* adding faulty val before aes and adding last msg in enc */
        if (i == (m-1)){
            /* /1* printing the intermediate state val for checking *1/ */
            /* printf("\n\ninter state val:"); */
            /* print(&cip[4*i], 128); */

            xr(&cip[4*i], fval, 128);
        }

        aes(&cip[4*i], &state[0]);
        xr(&cip[4*i], &msg[4*i], 128);

        copy(&cip[4*i + 2], &state[8], (uint32_t)128);    xr(&cip[4*i + 2], &state[12], 128);  aes(&cip[4*i + 2], &state[4]);
        xr(&cip[4*i + 2], &msg[4*i + 2], 128);

        R(state, &msg[4*i], &msg[4*i + 2]);
        }}


void frocca_s_enc( uint64_t *state, uint64_t *cip, uint64_t *tag, uint64_t *k0, uint64_t *k1, uint64_t *nonce, 
                uint64_t *ad, uint64_t *msg, uint32_t ad_len_bar, uint32_t msg_len_bar, uint64_t *fval){
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

        fenc(state, msg, cip, fval);
        }
    }


