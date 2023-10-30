/* gist: this is the improvement state recovery attack of rocca-s. Here the fault structure is like, we can give 4 random */
/* byte faults in each col of the state of aes. we give 4 such faults to reduce the state size of to 2^{16} */
/* ----------------------------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define msg_len 4*128
#define ad_len 256

#include "my_lib.h"
#include "aes.h"
#include "inv_aes.h"
#include "oracle.h"
#include "foracle.h"
#include "attack.h"

int main(){
    srand48(time(NULL));

    /* here we are assuming the len of msg and ad is same as its bar len */
    uint32_t ad_len_bar = ad_len;
    uint32_t msg_len_bar = msg_len;

    uint64_t *k0 = mem_alloc(128);
    uint64_t *k1 = mem_alloc(128);
    uint64_t *nonce = mem_alloc(128);
    uint64_t *msg = mem_alloc(msg_len_bar);
    uint64_t *ad = mem_alloc(ad_len_bar);
    uint64_t *tag = mem_alloc(2*128);


    /* -------------------------------------------------------------------------------------- */
    /* third test vector */
    /* -------------------------------------------------------------------------------------- */
    /* msg */
    insert(&msg[0], 0x0, 0x0);
    insert(&msg[2], 0x0, 0x0);
    insert(&msg[4], 0x0, 0x0);
    insert(&msg[6], 0x0, 0x0);

    /* keys k0 and k1 */
    insert(k0, 0x0123456789abcdef, 0x0123456789abcdef);
    insert(k1, 0x0123456789abcdef, 0x0123456789abcdef);

    /* associate data */
    insert(&ad[0], 0x0123456789abcdef, 0x0123456789abcdef);
    insert(&ad[2], 0x0123456789abcdef, 0x0123456789abcdef);

    /* nonce */
    insert(nonce, 0x0123456789abcdef, 0x0123456789abcdef);

    /* -------------------------------------------------------------------------------------- */
    /* fault oracle part */
    /* -------------------------------------------------------------------------------------- */
    /* At each row we give random 4 byte faults at each col */
    for (uint8_t row=0; row<4; row++){
        uint64_t *state = mem_alloc(7*128);
        /* -------------------------------------------------------------------------------------- */
        /* oracle part */
        /* -------------------------------------------------------------------------------------- */
        uint64_t *cip = mem_alloc(msg_len_bar);
        uint64_t *tag = mem_alloc(128);

        rocca_s_enc(state, cip, tag, k0, k1, nonce, ad, msg, ad_len_bar, msg_len_bar);

        /* generating four random epsilon */
        uint16_t epsilon[4] = {0};
        for (uint8_t i=0; i<4; i++){
            epsilon[i] = rnd()%256; 
        }

        uint64_t *fval = mem_alloc(128);
        /* generating fault by giving random byte faults at each col */
        for (uint8_t col=0; col<4; col++){
            uint64_t *ftemp = mem_alloc(128);
            ftemp[1] = epsilon[col]&0xff;  shift(ftemp, 32*col + 8*row, 128, "left");

            xr(fval, ftemp, 128);
            free(ftemp);
            }

        uint64_t *fstate = mem_alloc(7*128);
        uint64_t *fcip = mem_alloc(msg_len_bar);

        frocca_s_enc(fstate, fcip, tag, k0, k1, nonce, ad, msg, ad_len_bar, msg_len_bar, fval);


        /* cip diff is to store the output cip diff */
        uint64_t *cip_diff = mem_alloc(msg_len_bar);
        copy(cip_diff, cip, msg_len_bar);
        xr(cip_diff, fcip, msg_len_bar);

        find_state(cip_diff, fval, row);
    }
}







