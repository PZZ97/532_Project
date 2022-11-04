
//input: get_packet()

typedef unsigned char HASH;
typedef unsigend int CHUNK_idx  // index of unique chunk
#define  HASH_SIZE 32   //bytes
unordered_map<HASH*,CHUNK_idx> umap;

uint64_t hash_func(unsigned char* input, unsigned int pos)
{
	// put your hash function implementation here
	uint64_t hash = 0;
	for (int i = 0; i < WIN_SIZE; i++) {
		hash += int(input[pos + WIN_SIZE - 1 - i]) * pow(PRIME, i + 1);
	}
	return hash;
}

uint64_t hash_func2(unsigned char* input, unsigned int pos, uint64_t hash_res)
{
	return hash_res * PRIME - int(input[pos-1]) * pow(PRIME, WIN_SIZE + 1) + int(input[pos-1 + WIN_SIZE]) * PRIME;;
}

void cdc(unsigned char* buff, unsigned int buff_size, queue<int>& chunk_index)
{
	uint64_t hash = 0;
	for (unsigned int i = WIN_SIZE; i < buff_size - WIN_SIZE; i++) {
		if (i == WIN_SIZE) {
			hash = hash_func(buff, i);
		}
		else {
			hash = hash_func2(buff, i, hash);
		}
		if ((hash % MODULUS) == TARGET) {
			chunk_index.push_back(i);
		}
	}

}

#define CHUNK_SIZE 64
#define TOTAL_LEN_LEN 8

int k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t right_rot(uint32_t value, unsigned int count)
{
	return value >> count | value << (32 - count);
}

void SHA_256(CHUNK_idx q_chunk_index, char* packet, unsigned int packet_size, HASH* hash_value)
{
	int h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	unsigned i, j;

    string chunk = packet;
    chunk.append(1);
    while (chunk.length < 512){
        chunk.append(0);
    }

    uint32_t ah[8];

    const uint8_t *p = chunk;

    /* Initialize working variables to current hash value: */
    for (i = 0; i < 8; i++)
        ah[i] = h[i];

    /* Compression function main loop: */
    for (i = 0; i < 4; i++) {
        uint32_t w[16];

        for (j = 0; j < 16; j++) {
            if (i == 0) {
                w[j] = (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 |
                    (uint32_t) p[2] << 8 | (uint32_t) p[3];
                p += 4;
            } else {
                /* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array: */
                const uint32_t s0 = right_rot(w[(j + 1) & 0xf], 7) ^ right_rot(w[(j + 1) & 0xf], 18) ^ (w[(j + 1) & 0xf] >> 3);
                const uint32_t s1 = right_rot(w[(j + 14) & 0xf], 17) ^ right_rot(w[(j + 14) & 0xf], 19) ^ (w[(j + 14) & 0xf] >> 10);
                w[j] = w[j] + s0 + w[(j + 9) & 0xf] + s1;
            }
            const uint32_t s1 = right_rot(ah[4], 6) ^ right_rot(ah[4], 11) ^ right_rot(ah[4], 25);
            const uint32_t ch = (ah[4] & ah[5]) ^ (~ah[4] & ah[6]);
            const uint32_t temp1 = ah[7] + s1 + ch + k[i << 4 | j] + w[j];
            const uint32_t s0 = right_rot(ah[0], 2) ^ right_rot(ah[0], 13) ^ right_rot(ah[0], 22);
            const uint32_t maj = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
            const uint32_t temp2 = s0 + maj;

            ah[7] = ah[6];
            ah[6] = ah[5];
            ah[5] = ah[4];
            ah[4] = ah[3] + temp1;
            ah[3] = ah[2];
            ah[2] = ah[1];
            ah[1] = ah[0];
            ah[0] = temp1 + temp2;
        }
    }

    /* Add the compressed chunk to the current hash value: */
    for (i = 0; i < 8; i++)
        h[i] += ah[i];
	

	/* Produce the final hash value: */
	for (i = 0, j = 0; i < 8; i++)
	{
		hash_value[j++] = (uint8_t) (h[i] >> 24);
		hash_value[j++] = (uint8_t) (h[i] >> 16);
		hash_value[j++] = (uint8_t) (h[i] >> 8);
		hash_value[j++] = (uint8_t) h[i];
	}
}

/*
[   ]
*/
bool deduplication(unsigned int chunk_index,HASH& hash_value){
    //
    if(umap[hash_value]==0){
        umap[hash_value] =chunk_index;
        //call LZW
        return true;
    }
    //send chunk_index
    return false;
}

void LZW(int chunk_start,int chunk_end,string &s1,unsigned int packet_size,vector<unsigned char> &output_code){

    unordered_map<string, int> table;
    // build the original table 
    for (int i = 0; i <= 255; i++) {
        string ch = "";
        ch += char(i);
        table[ch] = i;
    }
    string p = "", c = "";
    p += s1[0];
    int code = 256;
    int length = chunk_end-chunk_start+1;
    for (int i = 0; i <length; i++) {
        if (i != s1.length() - 1)
            c += s1[chunk_start+i + 1];
        if (table.find(p + c) != table.end()) {
            p = p + c;
        }
        else {
            cout << p << "\t" << table[p] << "\t\t"
                 << p + c << "\t" << code << endl;
            output_code.push_back(table[p]);
            table[p + c] = code;
            code++;
            p = c;
        }
        c = "";
    }
    // cout << p << "\t" << table[p] << endl;
    output_code.push_back(table[p]);
    return output_code;
}

queue<pair<CHUNK_idx,int>> q;
int main(){


    //get_packet()


    CDC( packet,packet_size,  q);   // queue<pair<CHUNK_idx,int>> q;
    std::string s1(reinterpret_cast<char*>(packet));
    while(q.size()>0){
        pair<CHUNK_idx,int> index =q.front();
        q.pop();
        HASH hash_value[HASH_SIZE];
        SHA_256(index.first, packet, packet_size,  hash_value);

        if( deduplication(index.first,hash_value)){
            // acquire start index and end  index
            // LZW(int chunk_start,int chunk_end,char* packet,unsigned int packet_size,unsigned char* output,unsigned char *output_size);
            vector<unsigned char> output_code;
            LZW(chunk_start,chunk_end,s1,packet_size,output_code);
            //ssend (LZW)
        }
        else{
            //send index.first
        }
    }

}