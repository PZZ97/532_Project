
//input: get_packet()

typedef unsigned char HASH;
typedef unsigend int CHUNK_idx  // index of unique chunk
#define  HASH_SIZE 32   //bytes
unordered_map<HASH*,CHUNK_idx> umap;

void CDC( char* packet, unsigned int packet_size, queue<pair<CHUNK_idx,int>>& q_chunk_index){
    
}
// hash_value[HASH_SIZE]
void SHA_256(CHUNK_idx q_chunk_index,char* packet, unsigned int packet_size, HASH* hash_value){
    // accelerate on HW
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
void LZW(int chunk_start,int chunk_end,char* packet,unsigned int packet_size,unsigned char* output,unsigned char* output_size){

}

queue<pair<CHUNK_idx,int>> q;
int main(){


    //get_packet()


    CDC( packet,packet_size,  q);   // queue<pair<CHUNK_idx,int>> q;
    while(q.size()>0){
        pair<CHUNK_idx,int> index =q.front();
        q.pop();
        HASH hash_value[HASH_SIZE];
        SHA_256(index.first, packet, packet_size,  hash_value);

        if( deduplication(index.first,hash_value)){
            // acquire start index and end  index
            LZW(int chunk_start,int chunk_end,char* packet,unsigned int packet_size,unsigned char* output,unsigned char *output_size);
            //ssend (LZW)
        }
        else{
            //send index.first
        }
    }

}