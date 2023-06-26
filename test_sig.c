#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "params.h"
#define t1_offset 32
#define s1_offset 32
#define s2_offset 32+s1_len
#define t__offset 32+s1_len+s2_len

#define z__offset 0
#define c__offset z__len
#define h__offset z__len+c__len
#define karatsuba_recursions 4

#define SHAKE128_RATE 168
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))
#define NROUNDS 24
#define BLOCKS 3

void sign_power_of_two(uint32_t* signature, uint32_t* sk);
void sam(uint32_t* out_buffer, uint32_t *seed);
void hash_init(unsigned char*state);
void hash_absorb(unsigned char* state, uint32_t* in, size_t len);
void hash_gen(uint32_t* output, unsigned char *state);
void H(uint32_t* c, uint32_t* rho, uint32_t* t1, uint32_t* w1);
void unpack_sk(uint32_t* sk, uint32_t* rho, uint32_t* s1, uint32_t* s2, uint32_t* t);
void decompose(uint32_t *r1, uint32_t *r0, uint32_t  r , uint32_t base);
void highbits (uint32_t *r1, uint32_t  r , uint32_t base);
unsigned char makehint (uint32_t  z , uint32_t r, uint32_t base);
void poly_mult_karatsuba           (uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n, size_t recursions);
void poly_mult_mod_karatsuba       (uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n, size_t recursions);
void poly_mat_vec_mult_mod_karatsuba(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t k, size_t l, size_t n, size_t recursions);

#include "../polynomial_multiplication/karatsuba.h"
#include "../dilithium_crypto/noise.h"
#include "../dilithium_rejection/rejection.h"
#define matrix_index(i,j,m,n) (i+j*m)
#define matrix_len(m,n) (m*n)

void sign_power_of_two(uint32_t* signature, uint32_t* sk)
{

    uint32_t rounds = 0;
    uint32_t A [A__len];
    uint32_t t [t__len],t0[t__len],t1[t__len];
    uint32_t s1[s1_len],s2[s2_len];
    uint32_t y [y__len],w [w__len],w1[w__len],z  [z__len];
    uint32_t r [r__len],r0[r__len],r1[r__len],ct0[t__len];

    uint32_t rho[32],rhoprime[32+48];
    uint32_t c [c__len],h[t__len];

    unpack_sk(sk,rho,s1,s2,t);
    sam(A,rho);
    for(uint32_t i = 0; i < t__len; ++i) decompose(&t1[i],&t0[i], t[i],dilithium_d);
    rej:
        ++rounds;
        for(uint32_t i = 0; i < 20;++i) ((uint32_t*)rhoprime)[i] = rand_uint32_t();

        uint16_t nonce = 0;
        for(uint32_t i = 0; i < dilithium_l; ++i) large_bounded_noise_generation_256(&y[i*dilithium_n],rhoprime,nonce++);

        poly_mat_vec_mult_mod_karatsuba(w,A,y,dilithium_k,dilithium_l,dilithium_n,karatsuba_recursions);

        for(uint32_t i = 0; i < w__len; ++i) highbits(&w1[i],w[i],dilithium_gamma);
        /// --------------------------------------------------------------------------------- ///
        /// --------------------------------------------------------------------------------- ///
        /// --------------------------------------------------------------------------------- ///
        H(c,rho,t1,w1);
        poly_binary_mult(z,c,s1,dilithium_n,dilithium_l);
        poly_add(z,z,y,z__len);
        poly_binary_mult(ct0,c,s2,dilithium_n,dilithium_k);
        poly_copy(r,w,w__len);
        poly_sub(r,r,ct0,t__len);
        for(uint32_t i = 0; i < r__len; ++i) decompose(&r1[i],&r0[i],r[i],dilithium_gamma);
        if(rejection(z ,z__len,((1<< dilithium_gamma   )-dilithium_beta))) goto rej;
        if(rejection(r0,r__len,((1<<(dilithium_gamma-1))-dilithium_beta))) goto rej;
        poly_binary_mult(ct0,c,t0,dilithium_n,dilithium_k);
        poly_add(r,r,ct0,t__len);
        if(rejection(ct0,t__len,((1<<(dilithium_gamma-1))              ))) goto rej;
        for(uint32_t i = 0; i < t__len;++i) ct0[i] = -ct0[i];
        for(uint32_t i = 0; i < t__len;++i) h[i] = makehint(ct0[i],r[i],dilithium_gamma);
        pack_signature(signature,z,h,c);
}

void sam(uint32_t* out_buffer,uint32_t *seed) /// len in 32 bits
{
    unsigned char* it = (unsigned char*)out_buffer;
    shake128(it,256*5*4*sizeof(uint32_t),seed,32);
    
}
void hash_init(unsigned char*state)
{
    memset(state,0,200);
}

void hash_absorb(unsigned char* state, uint32_t *in, size_t len)
{
    shake128_absorb((uint64_t*)state,(uint32_t*) in,len/sizeof(uint32_t));
}

void hash_gen(uint32_t* output, unsigned char *state)
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

void H(uint32_t* c, uint32_t* rho, uint32_t* t1, uint32_t* w1)
{
    unsigned char state[200];
    hash_init(state);
    hash_absorb(state, (uint32_t *)rho,8);
    hash_absorb(state, t1,t__len);
    hash_absorb(state, w1, w__len);
    hash_gen(c,state);
}

void unpack_sk(uint32_t* sk, unsigned char* rho, uint32_t* s1, uint32_t* s2, uint32_t* t)
{
    memcpy(rho,sk,32);
    for(uint32_t i = 0; i < s1_len; ++i) s1[i] = sk[i+s1_offset];
    for(uint32_t i = 0; i < s2_len; ++i) s2[i] = sk[i+s2_offset];
    for(uint32_t i = 0; i < t__len; ++i) t [i] = sk[i+t__offset];
}

void decompose(uint32_t *r1, uint32_t *r0, uint32_t  r , uint32_t base)
{
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask>>1)+1;
    uint32_t r0p,b;
    r0p = (r<<(32-base));
    b   = (-(r0p>>(31)));
    b   = b<<base;
    r0p = (r0p>>(32-base));

    *r0 = r0p^b;
    *r1  = ((r+d_1)>>base);
}

void highbits(uint32_t *r1, uint32_t  r , uint32_t base)
{
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask>>1)+1;
    uint32_t r1p;
    r1p  = ((r+d_1)>>base);
    *r1 = r1p;
}
unsigned char makehint             (uint32_t  z , uint32_t r, uint32_t base)
{
    uint32_t r1,v1;
    highbits(&r1, r  , base);
    highbits(&v1, r+z, base);
    return (r1==v1)?0:1;
}

void poly_mult_karatsuba(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n, size_t recursions)
{
    const size_t n0 = n>>0;
    const size_t n1 = n>>1;
    if(recursions>0)
    {
        __attribute__((aligned(32))) uint32_t pCC[n0];

        poly_add(&pC[0],&pA[0],&pA[n1],n1);
        poly_add(&pC[n1],&pB[0],&pB[n1],n1);
        poly_mult_karatsuba(&pCC[0],&pC[0],&pC[n1],n1,recursions-1);
        poly_mult_karatsuba(&pC [0],&pA[0],&pB[0 ],n1,recursions-1);
        poly_sub(&pCC[0],&pCC[0],&pC[0 ],n0-1);
        poly_mult_karatsuba(&pC[n0],&pA[n1],&pB[n1],n1,recursions-1);
        poly_sub(&pCC[0],&pCC[0],&pC[n0],n0-1);
        pC[n0-1] = 0;
        poly_add(&pC[n1],&pC[n1],&pCC[0],n0-1);
    }else
    {
        poly_mult_schoolbook(&pC[0 ],&pA[0 ],&pB[0 ],n0);
    }
}

#define matrix_index(i,j,m,n) (i+j*m)
#define matrix_len(m,n) (m*n)

void poly_mult_mod_karatsuba(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n, size_t recursions)
{
    /// does not work with STM32F1

    uint32_t pCC[2*n];
    poly_mult_karatsuba(&pCC[0],pA,pB,n,recursions);
    pCC[2*n-1] = 0;
    poly_sub(pC,pCC,&pCC[n],n);

    /*
    poly_mult_karatsuba(&pC[0],pA,pB,n,recursions);
    pC[2*n-1] = 0;
    poly_sub(pC,pC,&pC[n],n);*/
}

void poly_mat_vec_mult_mod_karatsuba(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t k, size_t l, size_t n, size_t recursions)
{
    for(uint32_t i = 0; i < k; ++i)
    {
        poly_mult_mod_karatsuba(&pC[matrix_index(i,0,k,1)*n],&pA[matrix_index(i,0,k,l)*n],&pB[matrix_index(0,0,l,1)*n],n, recursions);
        for(uint32_t j = 1; j < l; ++j)
        {
            uint32_t tmp[n];
            poly_mult_mod_karatsuba(tmp,&pA[matrix_index(i,j,k,l)*n],&pB[matrix_index(j,0,l,1)*n],n, recursions);
            poly_add(&pC[matrix_index(i,0,k,1)*n],&pC[matrix_index(i,0,k,1)*n],tmp,n);
        }
    }
}

