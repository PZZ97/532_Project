#ifndef __SOURCE_H__
#define __SOURCE_H__
#define HASH_SIZE 256/8

#include <array>
#include <queue>

#include <string.h>
#include <wolfssl/wolfcrypt/sha.h>
typedef unsigend int CHUNK_idx_t;  // index of unique chunk
typedef unsigned int CHUNK_pos_t;  // index of chunk end pos in packet buffer
typedef std::queue<pair<CHUNK_pos_t,CHUNK_idx_t>> IDXQ;

typedef std::array<unsigned char,HASH_SIZE> HASH;

//function call inside CDC
uint64_t hash_func(unsigned char* input, unsigned int pos);
uint64_t hash_func2(unsigned char* input, unsigned int pos, uint64_t hash_res);

// CDC
/*
    @ buff： array acquired from get_packet()
    @ buff_size: buff size
    @ chunk_index: queue used to store pair of <chunk end position in the buff, unique chunk number>
*/
// void cdc(unsigned char* buff, unsigned int buff_size, queue<int>& chunk_index);
void cdc(unsigned char* buff, unsigned int buff_size, IDXQ& chunk_index);



// #define CHUNK_SIZE 64
// #define TOTAL_LEN_LEN 8
// uint32_t right_rot(uint32_t value, unsigned int count)
// void SHA_256(CHUNK_pos_t chunk_index, char* packet, unsigned int packet_size, HASH& hash_value)
/*
    @ begin: chunk start position
    @ end: chunk end position
    @ packet:   packet array
    @ packet_size: packet size
    @ hash_value: OUTPUT
*/

void SHA_384_HW(CHUNK_pos_t begin,CHUNK_pos_t end, char* packet, unsigned int packet_size, HASH& hash_value);


// deduplication
CHUNK_idx_t deduplication(CHUNK_idx_t chunk_index,HASH& hash_value);


// LZW
/*
    @ chunk_start： current chunk's start position
    @ chunk_end:    current chunk's end position
    @ s1 : chunk in string type
    @ packet_size: packet size
    @ output_code: output
*/
void LZW(int chunk_start,int chunk_end,string &s_packet,unsigned int packet_size,vector<unsigned char> &output_code);

#endif