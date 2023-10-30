/* gist: random bit fault attack on rocca-s. This is a state recovery attack. Here after giving random bit faults at */
/* each col ([0, 31], [32, 63], [64, 95], [96, 127]) we are recovering the state. */
/* ----------------------------------------------------------------------------------------------- */

#include <iostream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#define msg_len 4*128
#define ad_len 256

/* this is for the shifting in cmy_lib */
#define LEFT 0
#define RIGHT 1

#define NO_OF_TIMES 32

using namespace std;

#include "cmy_lib.h"
#include "aes_cpp.h"
#include "inv_aes_cpp.h"
#include "oracle_cpp.h"
#include "foracle_cpp.h"
#include "attack.h"



int main(){
    srand48(time(NULL));
    uint32_t ad_len_bar = ad_len;
    uint32_t msg_len_bar = msg_len;

    uint64_t *k0 = mem_alloc(128);
    uint64_t *k1 = mem_alloc(128);
    uint64_t *nonce = mem_alloc(128);
    uint64_t *msg = mem_alloc(msg_len_bar);
    uint64_t *ad = mem_alloc(ad_len_bar);

    /* -------------------------------------------------------------------------------------- */
    /* test vector */
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

    /* initializing state list for 16 cells */
    vector <vector <int>> state_list;

    /* giving all possible vals for all the cells. Idea is, keep updating the state list for each of the faults */
    for (uint8_t cell=0; cell<16; cell++){
        vector <int> state_val;
        /* each cell can contain 2^8 vals */
        for (int16_t val=0; val<256; val++){
            state_val.push_back(val);
        }
        state_list.push_back(state_val);
    }

    for (uint8_t times=0; times<NO_OF_TIMES; times++){
        rand_alloc(msg, msg_len_bar);

        uint64_t *state = mem_alloc(7*128);
        uint64_t *cip = mem_alloc(msg_len_bar);
        uint64_t *tag = mem_alloc(2*128);

        rocca_s_enc(state, cip, tag, k0, k1, nonce, ad, msg, ad_len_bar, msg_len_bar);

        /* -------------------------------------------------------------------------------------- */
        /* fault oracle part */
        /* -------------------------------------------------------------------------------------- */
        /* giving random bit fault in the state */
        uint16_t bit = rnd()%128;

        /* initializing faulty val */
        uint64_t *fval = mem_alloc(128);
        /* from our convention col0 is the right most col (i.e. bits [0, 31]) */
        /* generating 1-bit input fault difference */
        fval[1] = 1&1;  shift(fval, bit, 128, LEFT);

        /* initializing faulty state and faulty cip text */
        uint64_t *fstate = mem_alloc(7*128);
        uint64_t *fcip = mem_alloc(msg_len_bar);

        frocca_s_enc(fstate, fcip, tag, k0, k1, nonce, ad, msg, ad_len_bar, msg_len_bar, fval);

        /* cip diff is to store the output cip diff */
        uint64_t *cip_diff = mem_alloc(msg_len_bar);
        copy(cip_diff, cip, (uint32_t)msg_len_bar);
        xr(cip_diff, fcip, msg_len_bar);

        /* -------------------------------------------------------------------------------------- */
        /* attack part */
        /* -------------------------------------------------------------------------------------- */
        state_list = find_random_bit_state(cip_diff, state_list);

        /* freeing the local vars */
        free(state);
        free(cip);
        free(tag);
        free(cip_diff);
    }

   /* for printing purpose of the reduced state list */
    for (int i=0; i<state_list.size(); i++){
        cout << "\n\nfor cell " << i << ": ";

        for (int j=0; j< state_list[i].size(); j++){
            cout << hex << state_list[i][j] << ", ";
        }
    }
}






