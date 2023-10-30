
void find_state(uint64_t *cip_diff, uint64_t *fval, uint8_t row){
    /* retrieving the intermediate 128-bit where one round aes has applied at the enc process */
    uint64_t *inter_cip_diff = mem_alloc(128);
    copy(inter_cip_diff, &cip_diff[4], (uint32_t)128);

    /* inverting one round aes at the output of sbox operation */
    inv_mc(inter_cip_diff);
    inv_sr(inter_cip_diff);

    /* for each col in mc state */
    for (int16_t col=3; col>=0; col--){
        printf("\nfor cell %d:\t", (32*col + 8*row)/8);

        for (int16_t byte_val=0; byte_val<256; byte_val++){
            uint64_t *state = mem_alloc(128);

            /* making the state with all possible byte vals in the 0th byte only */
            state[1] = byte_val&0xff;   shift(state, 32*col + 8*row, 128, "left");

            /* -------------------------------------------------------------------- */
            /* for fault */
            /* -------------------------------------------------------------------- */
            uint64_t *fstate = mem_alloc(128);

            /* making the faulty state with all possible byte vals in the 0th byte only */
            fstate[1] = byte_val&0xff;  shift(fstate, 32*col + 8*row, 128, "left");
            xr(fstate, fval, 128);

            /* applying operations of aes */
            sbox(state);    sbox(fstate);

            /* taking the diff of the state vals */
            xr(state, fstate, 128);

            xr(state, inter_cip_diff, 128);
            shift(state, 32*col + 8*row, 128, "right");

            if((state[1]&0xff) == 0){
                printf("%x, ", byte_val);
            }

            free(state);
            free(fstate);

            /* /1* print the values for which the diff matches *1/ */
            /* if (check_eq(state, &cip_diff[4], 128) == 1){ */
            /*     printf("%x, ", byte_val); */
            /* } */
        }
    }
}
