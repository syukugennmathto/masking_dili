#include "./hash.h"
#include "../dilithium/params.h"
#include "../dilithium_crypto/fips202.h"
#define BLOCKS 3

void shake128_absorb(uint64_t *s,
                     const unsigned char *input,
                     unsigned long long inlen)
{
  keccak_absorb(s, SHAKE128_RATE, input, inlen, 0x1F);
}

void shake128_squeezeblocks(unsigned char *output,
                            unsigned long nblocks,
                            uint64_t *s)
{
  keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);
}

int main() {
    return 0;
}

void hash_init(unsigned char*state)
{
    memset(state,0,200);
}

void hash_absorb(unsigned char* state, uint32_t* in, size_t len)
{
    shake128_absorb((uint64_t*)state,(unsigned char*)in,len/sizeof(uint32_t));
}

void hash_gen(unsigned char *output, unsigned char *state)
{
    memset(output,0,(dilithium_n-dilithium_hash_hw));
    unsigned char buffer[BLOCKS*SHAKE128_RATE];
    unsigned int counter = dilithium_n-dilithium_hash_hw;
    while( counter<dilithium_n)
    {
        shake128_squeezeblocks(buffer,BLOCKS,(uint64_t*)state);
        uint32_t i = 0;
        while((counter<dilithium_n)&& (i<BLOCKS*SHAKE128_RATE) )
        {
            uint32_t j = buffer[i+0]%counter;
            output[counter] = output[j];
            if(buffer[i+1]&0x1)
            {
                output[j] = 1;
            }else
            {
                output[j] = -1;
            }
            i += 2;
            ++counter;
        }
    }
}

void H(unsigned char* c, unsigned char* rho, uint32_t* t1, uint32_t* w1)
{
    unsigned char state[200];
    hash_init(state);
    hash_absorb(state, (uint32_t *)rho,8);
    hash_absorb(state, t1,t__len);
    hash_absorb(state, w1, w__len);
    hash_gen(c,state);
}
