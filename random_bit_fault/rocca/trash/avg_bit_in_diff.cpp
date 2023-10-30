/* gist: the prog prints the avg input bit diff size for any output diff. The size is 3.97 */ 
/* ----------------------------------------------------------------------------------------------- */

#include <iostream>
#include <vector>
#include <cstdint>

#include <stdio.h>

using namespace std;

int main(){
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

    int avg_size = 0;
    for (int i=0; i<in_diff_bit_list.size(); i++){
       avg_size += in_diff_bit_list[i].size();
    }

    printf("\nsize: %.2f", (float)avg_size/256);
}
