/* gist: random bit fault attack on rocca. This is a state recovery attack. Here after giving random bit faults at */
/* each col ([0, 31], [32, 63], [64, 95], [96, 127]) we are recovering the state. */

/* result: (using 100 times) */
/*     for 10 faults, reduced state size: 85.89 */
/*     for 12 faults, reduced state size: 78.46 */
/*     for 14 faults, reduced state size: 72.62 */
/*     for 16 faults, reduced state size: 66.56 */
/*     for 18 faults, reduced state size: 60.56 */

/*     for 20 faults, reduced state size: 55.82 */
/*     for 22 faults, reduced state size: 50.82 */
/*     for 24 faults, reduced state size: 46.95 */
/*     for 26 faults, reduced state size: 42.73 */
/*     for 28 faults, reduced state size: 39.01 */

/*     for 30 faults, reduced state size: 35.64 */
/*     for 32 faults, reduced state size: 33.92 */
/*     for 34 faults, reduced state size: 29.80 */
/*     for 36 faults, reduced state size: 26.61 */
/*     for 38 faults, reduced state size: 25.17 */

/*     for 40 faults, reduced state size: 23.16 */
/*     for 42 faults, reduced state size: 21.16 */
/*     for 44 faults, reduced state size: 18.57 */
/*     for 46 faults, reduced state size: 17.24 */
/*     for 48 faults, reduced state size: 14.20 */
/*     for 50 faults, reduced state size: 13.45 */
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
#include <math.h>


#define msg_len 4*128
#define ad_len 256

/* this is for the shifting in cmy_lib */
#define LEFT 0
#define RIGHT 1

#define NO_OF_TIMES 47
#define NO_OF_EXP 100

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

    float avg_state_list_size = 0;
    for (uint8_t exp=0; exp<NO_OF_EXP; exp++){
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


        /* state list size is to calculate at each exp the reduced state size */       
        for (uint8_t times=0; times<NO_OF_TIMES; times++){
            uint64_t *state = mem_alloc(7*128);
            uint64_t *cip = mem_alloc(msg_len_bar);
            uint64_t *tag = mem_alloc(2*128);

            rocca_s_enc(state, cip, tag, k0, k1, nonce, ad, msg, ad_len_bar, msg_len_bar);

            /* /1* -------------------------------------------------------------------------------------- *1/ */
            /* /1* fault oracle part *1/ */
            /* /1* -------------------------------------------------------------------------------------- *1/ */
            /* /1* giving random bit faults in each of the cols *1/ */
            /* uint8_t bit[4] = {0}; */
            /* for (uint8_t col=0; col<4; col++){ */
            /*     bit[col] = rnd()%32; */ 
            /* } */

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

           /* /1* for printing purpose of the reduced state list *1/ */
           /*  for (int i=0; i<state_list.size(); i++){ */
           /*      cout << "\n\nfor cell " << i << ": "; */

           /*      for (int j=0; j< state_list[i].size(); j++){ */
           /*          cout << state_list[i][j] << ", "; */
           /*      } */
           /*  } */
        }

        /* -------------------------------------------------------------------------------------- */
        /* calculating reduced state space size */
        /* -------------------------------------------------------------------------------------- */
        float state_list_size = 0;

        /* for printing purpose of the reduced state list */
        for (int i=0; i<state_list.size(); i++){
            state_list_size += log(state_list[i].size())/log(2);
        }

        printf("\nstate list size: %.2f\n", (state_list_size));
        avg_state_list_size += (state_list_size);
    }

    printf("\navg list size: %.2f\n", (avg_state_list_size/NO_OF_EXP));
}






