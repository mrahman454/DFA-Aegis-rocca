/* gist: the random bit fault attack within 128-bit state on rocca-s cipher. */
/* ------------------------------------------------------------------------------------------------------------ */

/* find the non-zero cell */
uint8_t find_cell(uint64_t *state){
    uint8_t cell = 0;
    for (cell=0; cell<16; cell++){
        /* extracting the cell val */
        uint8_t cell_val = (state[1 - (cell/8)] >> (8*(cell%8)))&0xff;

        /* if the cell val is non-zero, then note the cell */
        if (cell_val != 0){
            break;
        }
    }
    return cell;
}


vector <vector <int>> find_random_bit_state(uint64_t *cip_diff, vector <vector <int>> state_list){
    /* the vector list corresp to the possible bit input diff for a output diff. The convention is, if the output diff is y, then */ 
    /* in_diff_bit_list[y] stores all possible input bit differences. The len of the list is (256 x *) as 256 many possible can be there */ 
    vector <vector <int>> in_diff_bit_list{{}, {4, 0, 6},  {3, 5, 7},  {3, 4, 1, 7},  {5, 0, 1},  {6, 1, 7},  {4, 0, 1, 5},  {7, 4, 1},  
    {7, 0, 4},  {7, 0, 5, 2, 3},  {5, 0, 6},  {6, 0, 7, 1, 3, 4},  {6, 0, 1, 3},  {4, 0, 1},  {7, 0},  {6, 0, 1, 7, 5, 3},  
    { 6, 3},  { 7, 0, 1, 3, 4},  { 4, 1, 6, 2},  { 3, 4},  { 7, 4, 1, 0},  { 3, 0, 6, 2},  { 6, 5, 7, 2, 3},  { 5, 2, 7},  
    { 5, 0, 2},  { 7, 0, 2},  { 7, 0, 3},  { 6, 7, 1, 2, 3},  { 6, 7, 1, 2, 4},  { 5, 1, 2},  { 6, 0, 2},  { 3, 0, 6},  
    { 5, 6, 2},  { 6, 5, 0, 2, 3},  { 6, 0, 5, 3},  { 5, 4, 7},  { 5, 0, 1, 3},  { 3, 1, 5},  { 3, 2},  { 6, 3, 1, 2},  
    { 4},  { 6, 5, 0, 2, 4},  { 7, 0, 1, 5, 6},  { 7, 6},  { 5, 7, 1, 6, 2, 4},  { 6, 5, 7, 0, 2, 1, 3},  { 7, 4, 1, 6},  { 6, 0, 1, 7},  
    { 3, 0, 2, 4},  { 6, 0, 7, 2, 3},  { 6, 7, 2, 3, 4},  { 4, 6, 2, 7},  { 7, 6, 2},  { 6, 0, 2, 3, 4},  { 6, 0, 1, 5, 2},  { 0, 1, 2},  
    { 0, 1, 2, 3, 4},  { 7, 3, 6, 0},  { 6, 0, 5, 7, 4},  { 4, 3, 0},  { 5, 1},  { 6, 2},  { 5, 2},  { 5, 3, 0, 4},  
    { 5, 4, 1},  { 6, 1},  { 5, 7, 1, 2, 4},  { 6, 0, 2, 7},  { 7},  { 7, 5, 6, 2},  { 4, 2},  { 7, 0, 1, 2, 3},  
    { 4, 0, 2, 7},  { 5, 6, 7, 2, 4},  { 4, 0, 2},  { 7, 0, 5, 2, 3, 4},  { 5, 0, 6, 3, 4},  { 7, 1, 5},  { 0, 2},  { 4, 0},  
    { 3},  { 3, 0, 2, 7},  { 4, 3, 1, 5},  { 6, 0, 1, 2, 3},  { 5, 0, 1, 2, 4},  { 6, 5, 1, 7, 2},  { 3, 4, 1, 2},  { 3, 1, 2, 7},  
    { 5, 0, 1, 6, 3, 4},  { 6, 0, 1, 2, 4},  { 5, 0, 1, 6, 2, 4},  { 3, 5, 6},  { 4, 6},  { 5, 7, 1, 2, 3},  { 4, 7},  { 5, 1, 6},  
    { 6, 5, 1, 2, 4},  { 6, 5},  { 7, 0, 5, 6, 3, 4},  { 5, 4, 6, 0},  { 7, 6, 1, 5, 2, 3},  { 4, 0, 6, 2},  { 5, 6, 1, 7, 3},  { 6, 1, 2, 3, 4},  
    { 7, 1, 2, 3, 4},  { 5, 0, 6, 7},  { 6, 0, 5, 2, 3, 4},  { 7, 0, 5, 6, 3},  { 7, 0, 1, 5, 4},  { 3, 4, 1},  { 0, 1},  { 3, 6, 2},  
    { 7, 4, 1, 2},  { 4, 3, 6},  { 6, 0, 1, 5},  { 7, 4, 5, 2},  { 6, 5, 7, 3, 4},  { 5, 0, 1, 6, 3},  { 3, 2, 7},  { 4, 5, 6, 7},  
    { 5, 0, 2, 7},  { 7, 0, 5, 1, 2},  { 5, 6, 7, 1, 2, 3, 4},  { 7, 1, 2},  { 4, 1},  { 7, 0, 1, 5, 2, 3, 4},  { 3, 4, 2},  { 7, 5},  
    { 7, 0, 1, 5},  { 4, 5, 2},  { 7, 5, 0, 3, 4},  { 5, 0, 1, 3, 4},  { 6, 0, 1, 3, 4},  { 7, 0, 5, 1, 2, 4},  { 6, 5, 1, 7},  { 5, 0, 1, 2, 3, 4},  
    { 5, 4, 1, 2},  { 5, 0, 4},  { 6, 0, 1, 7, 4},  { 6, 3, 7},  { 3, 1},  { 4, 3, 2, 7},  { 7, 0, 1, 6, 2},  { 5},  
    { 3, 4, 6, 7},  { 5, 0, 1, 2},  { 6, 4, 2},  { 7, 0, 2, 3, 4},  { 7, 3, 1},  { 7, 3, 5, 2},  { 6, 7, 1, 2, 3, 4},  { 7, 0, 1, 2},  
    { 6, 1, 5, 2},  { 6, 0, 1, 2},  { 5, 7, 1, 3, 4},  { 3, 0, 1, 2},  { 1},  {7, 0, 1, 2, 4},  { 7, 3},  { 5, 0, 1, 6, 4},  
    { 7, 2},  { 3, 0, 1, 7},  { 6, 1, 2, 7},  { 3, 0, 5, 2},  { 5, 3, 6, 7},  { 5, 6, 1, 3, 4},  { 7, 0, 5, 6, 2, 3, 4},  { 3, 1, 6},  
    { 3, 0, 1, 4},  { 7, 0, 1, 2, 3, 4},  { 5, 6, 1, 7, 0, 4},  { 5, 0, 7, 6, 2, 3},  { 7, 0, 1, 5, 2, 3},  { 6, 0, 7, 4},  { 5, 6, 1, 7, 3, 4},  { 5, 4, 2, 3},  
    { 5, 0, 2, 3, 4},  { 5, 6, 1, 2, 3},  { 7, 5, 1, 0, 3},  { 5, 7, 2, 3, 4},  { 5, 0},  { 7, 0, 5},  { 5, 0, 2, 4},  { 3, 4, 7, 0},  
    { 3, 5}, {}, { 7, 0, 6, 1, 2, 4},  { 6, 5, 7},  { 3, 0, 1},  { 6, 5, 1, 7, 4},  { 6, 5, 1, 2, 3, 4},  { 6},  
    { 3, 5, 1, 6},  { 6, 0, 1},  { 5, 6, 1, 0, 2, 3},  { 5, 0, 6, 1, 2, 3, 4},  { 7, 5, 6, 2, 3, 4},  { 4, 1, 2},  { 5, 3, 4},  { 6, 0},  
    { 6, 5, 1, 0, 7, 3, 4},  { 6, 4, 7},  { 6, 0, 3, 4},  { 3, 1, 2},  { 6, 0, 7, 5, 2, 4},  { 6, 0, 1, 2, 3, 4},  { 5, 0, 1, 2, 3},  { 7, 0, 1, 6, 2, 5},  
    { 4, 0, 1, 2},  { 6, 3, 1, 4},  { 7, 0, 5, 3},  { 4, 0, 5, 7},  { 5, 1, 2, 3, 4},  { 6, 7, 1, 3, 4},  { 6, 4, 5, 2},  { 3, 6, 2, 7},  
    { 6, 0, 7, 2, 3, 4},  { 5, 3, 6, 4},  { 6, 4, 5, 1},  { 6, 1, 2},  { 0},  { 6, 0, 7},  { 7, 1, 5, 2},  { 6, 3, 5, 2},  
    { 6, 0, 1, 7, 3},  { 5, 3, 0},  { 5, 3, 2},  { 7, 1},  { 6, 0, 5, 2},  { 5, 4, 6},  { 5, 7, 1, 2, 3, 4},  { 6, 7, 0, 1, 2, 3},  
    { 5, 6, 2, 3, 4},  { 6, 3, 1, 7},  { 7, 5, 0, 2, 4},  { 3, 4, 7},  { 1, 2},  { 3, 0, 2},  { 7, 0, 1},  { 7, 0, 6, 3, 4},  
    { 4, 1, 6},  { 2},  { 4, 0, 1, 6},  { 3, 1, 5, 2},  { 7, 4, 2},  { 4, 5},  { 5, 0, 6, 7, 2},  { 5, 0, 1, 7, 3, 4},  
    { 3, 0},  { 3, 4, 6, 2},  { 6, 0, 1, 7, 2, 3, 4},  { 6, 0, 7, 2, 4},  { 3, 4, 5, 7},  { 5, 3, 1, 7},  { 5, 4, 1, 7},  { 7, 0, 5, 6, 2, 1, 4}};


    /* retrieving the intermediate 128-bit where one round aes has applied at the enc process */
    uint64_t *inter_cip_diff = mem_alloc(128);
    copy(inter_cip_diff, &cip_diff[4], (uint32_t)128);

    /* inverting one round aes at the output of sbox operation */
    inv_mc(inter_cip_diff);
    inv_sr(inter_cip_diff);

    /* finding the cell where the vals become non-zero */    
    uint64_t cell = find_cell(inter_cip_diff);

    /* tmp state list is to store the reduced state vals */
    vector <int> tmp_state_list;

    /* taking tmp to extract the corresp byte val of the output diff */
    uint64_t *tmp = mem_alloc(128);
    copy(tmp, inter_cip_diff, (uint32_t)128);
    shift(tmp, 8*cell, 128, RIGHT);

    /* out_diff_byte takes the cell val of the diff */
    uint8_t out_diff_byte = tmp[1]&0xff;   
    free(tmp);

    for (int byte_val_idx=0; byte_val_idx< state_list[cell].size(); byte_val_idx++){
        /* taking the byte val from the idx */
        uint8_t byte_val = state_list[cell][byte_val_idx];

        /* taking all possible bits in the byte as we do not know the bit fault location */
        for (int16_t bit_idx=0; bit_idx<in_diff_bit_list[out_diff_byte].size(); bit_idx++){
            /* taking only those bits which can appear in as the input diff of the corresp output diff */
            int16_t bit = in_diff_bit_list[out_diff_byte][bit_idx];

            uint64_t *state = mem_alloc(128);

            /* making the state with reduced state vals in the corresponding byte position */
            state[1] = byte_val&0xff;   shift(state, 8*cell, 128, LEFT);

            /* -------------------------------------------------------------------- */
            /* for fault part */
            /* -------------------------------------------------------------------- */
            uint64_t *fstate = mem_alloc(128);

            /* making the faulty state with reduced state vals in the corresponding byte position */
            fstate[1] = byte_val&0xff;  shift(fstate, 8*cell, 128, LEFT);

            uint64_t *fval = mem_alloc(128);
            insert(fval, 0x0UL, 0x0UL);

            /* making the 128-bit fault by giving the diff in the corresponding cell */ 
            fval[1] = 1&1;  shift(fval, 8*cell + bit, 128, LEFT);

            xr(fstate, fval, 128);

            /* applying operations of aes */
            sbox(state);    sbox(fstate);

            /* taking the diff of the state and faulty state vals */
            xr(state, fstate, 128);

            /* here we have to check whether the coming state is equal with the cip diff or not, for this we are xoring the */ 
            /* recovered state diff with the original cip diff and checking whether its 0 in the corresp cell position or not */
            xr(state, inter_cip_diff, 128);

            shift(state, 8*cell, 128, RIGHT);

            if((state[1]&0xff) == 0){
                /* if the state val is a possible one then push the val in the list */
                tmp_state_list.push_back(byte_val);
            }

            free(state);
            free(fstate);
        }
    }

    /* updating the state list of the corresp cell */
    state_list[cell].clear();
    for (int i=0; i<tmp_state_list.size(); i++){
        state_list[cell].push_back(tmp_state_list[i]);
    }

    return state_list;
}
