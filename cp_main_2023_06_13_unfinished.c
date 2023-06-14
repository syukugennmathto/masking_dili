#include <stdio.h>
#include <stdlib.h>
#include "../dilithium/params.h"
#define BLOCKS 3

#define shares 2

#define dilithium_n       256
#define dilithium_k       5
#define dilithium_l       4
#define dilithium_nu      5
#define dilithium_d       14
#define dilithium_gamma   19
#define dilithium_hash_hw 60
#define dilithium_beta    235


#define A__len dilithium_n*dilithium_k*dilithium_l
#define t1_len dilithium_n*dilithium_k

#define s1_len dilithium_n*dilithium_l
#define s2_len dilithium_n*dilithium_k
#define t__len dilithium_n*dilithium_k
#define t0_len dilithium_n*dilithium_k

#define y__len dilithium_n*dilithium_l
#define w__len dilithium_n*dilithium_k
#define r__len dilithium_n*dilithium_k
#define h__len dilithium_n*dilithium_k
#define z__len dilithium_n*dilithium_l
#define c__len dilithium_n

#define pk_len 32+t1_len
#define sk_len 32+s1_len+s2_len+t__len
#define signature_len z__len+h__len+c__len

#define low_noise_bound   dilithium_nu
#define large_noise_bound (1 << dilithium_gamma) - 1
#define rand_uint32_t() lfsr_inc_3x2()
#define t1_offset 32
#define t1_offset 32
#define s1_offset 32
#define s2_offset 32+s1_len
#define t__offset 32+s1_len+s2_len

#define z__offset 0
#define c__offset z__len
#define h__offset z__len+c__len
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

extern uint32_t lfsr_state;
static const uint32_t lfsr_taps32[] = {0xFFFFFFFF, (1 << 31), (1 << 21), (1 << 1), (1 << 0), 0};

static uint32_t lfsr_inc_32()
{
    uint32_t tap = 0;
    int i = 1;

    while(lfsr_taps32[i])
        tap ^= !!(lfsr_taps32[i++] & lfsr_state);
    lfsr_state <<= 1;
    lfsr_state |= tap;
    lfsr_state &= lfsr_taps32[0];

    return lfsr_state;
}


void decompose(uint32_t *a0, uint32_t *r0, uint32_t  a, uint32_t base)
{
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask>>1)+1;
    uint32_t r0p,b;
    r0p = (a<<(32-base));
    b   = (-(r0p>>(31)));
    b   = b<<base;
    r0p = (r0p>>(32-base));

    *r0 = r0p^b;
    *a0  = ((a+d_1)>>base);
}
void highbits(uint32_t *r1, uint32_t  r , uint32_t base)
{
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask>>1)+1;
    uint32_t r1p;
    r1p  = ((r+d_1)>>base);
    *r1 = r1p;
}

void lowbits(uint32_t *r0, uint32_t  r , uint32_t base)
{
    uint32_t r0p,b;
    //activate_trigger_aux();
    r0p = (r<<(32-base));
    //desactivate_trigger_aux();
    b   = (-(r0p>>(31)));
    b   = b<<base;
    r0p = (r0p>>(32-base));
    r0p = r0p^b;
    *r0 = r0p;
}

uint32_t lowbits_2(uint32_t  r , uint32_t base)
{
    uint32_t r0p,b;
    r0p = (r<<(32-base));
    b   = (-(r0p>>(31)));
    b   = b<<base;
    r0p = (r0p>>(32-base));
    r0p = r0p^b;
    return r0p;
}

unsigned char makehint(uint32_t  z , uint32_t r, uint32_t base)
{
    uint32_t r1,v1;
    highbits(&r1, r  , base);
    highbits(&v1, r+z, base);
    return (r1==v1)?0:1;
}

uint32_t usehint(uint32_t  y , uint32_t r, uint32_t base)
{
    uint32_t r0,r1;
    decompose(&r1,&r0,r,base);
    if( y == 1 )
    {
        if( r0&(1<<(base-1)) )
        {
            --r1;
        }else
        {
            ++r1;
        }
    }
    return r1;
}



void pack_pk(uint32_t* pk, unsigned char* rho, uint32_t* t1)
{
    memcpy(pk,rho,32);
    for(uint32_t i = 0; i < t1_len; ++i)
    {
        pk[i+t1_offset]  =  t1[i];
    }
}


void unpack_pk(uint32_t* pk, unsigned char* rho, uint32_t* t1)
{
    memcpy(rho,pk,32);
    for(uint32_t i = 0; i < t1_len; ++i)
    {
        t1[i] = pk[i+t1_offset];
    }
}

void pack_sk(uint32_t* sk, unsigned char* rho, uint32_t* s1, uint32_t* s2, uint32_t* t)
{
    memcpy(sk,rho,32);
    for(uint32_t i = 0; i < s1_len; ++i) sk[i+s1_offset]  =  s1[i];
    for(uint32_t i = 0; i < s2_len; ++i) sk[i+s2_offset]  =  s2[i];
    for(uint32_t i = 0; i < t__len; ++i) sk[i+t__offset]  =  t [i];
}

void unpack_sk(uint32_t* sk, unsigned char* rho, uint32_t* s1, uint32_t* s2, uint32_t* t)
{
    memcpy(rho,sk,32);
    for(uint32_t i = 0; i < s1_len; ++i) s1[i] = sk[i+s1_offset];
    for(uint32_t i = 0; i < s2_len; ++i) s2[i] = sk[i+s2_offset];
    for(uint32_t i = 0; i < t__len; ++i) t [i] = sk[i+t__offset];
}

void pack_signature  (uint32_t* si, uint32_t* z, unsigned char* h, unsigned char* c)
{
    for(uint32_t i = 0; i < z__len; ++i) si[i+z__offset]  =  z[i];
    for(uint32_t i = 0; i < c__len; ++i) si[i+c__offset]  =  c[i];
    for(uint32_t i = 0; i < h__len; ++i) si[i+h__offset]  =  h[i];
}


void unpack_signature(uint32_t* si, uint32_t* z, unsigned char* h, unsigned char* c)
{
    for(uint32_t i = 0; i < z__len; ++i) z[i] = si[i+z__offset];
    for(uint32_t i = 0; i < c__len; ++i) c[i] = si[i+c__offset];
    for(uint32_t i = 0; i < h__len; ++i) h[i] = si[i+h__offset];
}

void poly_binary_mult       (uint32_t* pC, unsigned char* pA, uint32_t* pB, size_t n, size_t k);

static void poly_copy(uint32_t* pC, uint32_t* pA, size_t n)
{
    memcpy(pC,pA,n*sizeof(uint32_t));
}

static void poly_add(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n)
{
    for(uint32_t i = 0; i < n; i++)
    {
        pC[i] = pA[i] + pB[i];
    }
}

static void poly_sub(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n)
{
    for(uint32_t i = 0; i < n; i++)
    {
        pC[i] = pA[i] - pB[i];
    }
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

void sam(uint32_t* out_buffer, unsigned char *seed) /// len in 32 bits
{
    unsigned char* it = (unsigned char*)out_buffer;
    shake128(it,dilithium_n*dilithium_k*dilithium_l*sizeof(uint32_t),seed,32);
}

uint32_t small_noise_rejection_256(uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len)
{
    uint32_t ctr, pos;
    unsigned char t0, t1;

    ctr = pos = 0;
    while(ctr < out_len) {
        t0 = buffer[pos] & 0x0F;
        t1 = buffer[pos++] >> 4;

        if(t0 <= 2*low_noise_bound)
        out_buffer[ctr++] = low_noise_bound - t0;
        if((t1 <= (2*low_noise_bound)) && (ctr < out_len))
        out_buffer[ctr++] = low_noise_bound - t1;

        if(pos >= in_len)
        break;
    }
    return ctr;
}

void small_bounded_noise_generation_256(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce)
{
    const size_t SEEDBYTES = 32;
    unsigned int i, ctr;
    unsigned char inbuf[SEEDBYTES + 1];
    unsigned char outbuf[2*SHAKE256_RATE];
    uint64_t state[25];

    for(i= 0; i < SEEDBYTES; ++i)
        inbuf[i] = seed[i];
    inbuf[SEEDBYTES] = nonce;

    shake256_absorb(state, inbuf, SEEDBYTES + 1);
    shake256_squeezeblocks(outbuf, 2, state);

    ctr = small_noise_rejection_256(out_buffer, 256 , outbuf,2*SHAKE256_RATE);
    if(ctr < 256) {
        shake256_squeezeblocks(outbuf, 1, state);
        small_noise_rejection_256(out_buffer+ctr, 256 - ctr, outbuf,SHAKE256_RATE);
    }
}


uint32_t large_noise_rejection_256(uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len)
{
    uint32_t ctr, pos;
    uint32_t t0,t1;

    ctr = pos = 0;
    while(ctr < out_len) {

        t0  = buffer[pos];
        t0 |= (uint32_t)buffer[pos + 1] << 8;
        t0 |= (uint32_t)buffer[pos + 2] << 16;
        t0 &= 0x7FFFF;

        t1  = buffer[pos + 2] >> 4;
        t1 |= (uint32_t)buffer[pos + 3] << 4;
        t1 |= (uint32_t)buffer[pos + 4] << 12;
        t1 &= 0x7FFFF;

        pos += 5;

        if(t0 <= (2*large_noise_bound))
        out_buffer[ctr++] = large_noise_bound - t0;
        if((t1 <= (2*large_noise_bound)) && (ctr < out_len))
        out_buffer[ctr++] = large_noise_bound - t1;

        if(pos >= in_len)
            break;
    }
    return ctr;
}

void large_bounded_noise_generation_256(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce)
{
    const size_t SEEDBYTES = 32;
    const size_t CRHBYTES  = 48;
    unsigned int i, ctr;
    unsigned char inbuf[SEEDBYTES + CRHBYTES + 2];
    unsigned char outbuf[5*SHAKE256_RATE];
    uint64_t state[25];

    for(i= 0; i < SEEDBYTES + CRHBYTES; ++i)
        inbuf[i] = seed[i];
    inbuf[SEEDBYTES + CRHBYTES + 0] = nonce & 0xFF;
    inbuf[SEEDBYTES + CRHBYTES + 1] = nonce >>   8;

    shake256_absorb(state, inbuf, SEEDBYTES + CRHBYTES + 2);
    shake256_squeezeblocks(outbuf, 5, state);

    ctr = large_noise_rejection_256(out_buffer, 256 , outbuf,5*SHAKE256_RATE);
    if(ctr < 256) {
        shake256_squeezeblocks(outbuf, 1, state);
        ctr += large_noise_rejection_256(out_buffer+ctr, 256 - ctr, outbuf,SHAKE256_RATE);
    }
}



/// --------------------------------------------------------------------------- ///

uint32_t small_noise_rejection(uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len)
{
    uint32_t ctr, pos;
    unsigned char t0, t1;

    ctr = pos = 0;
    while(ctr < out_len) {
        t0 = buffer[pos] & 0x0F;
        t1 = buffer[pos++] >> 4;

        if(t0 <= 2*low_noise_bound)
        out_buffer[ctr++] = low_noise_bound - t0;
        if((t1 <= (2*low_noise_bound)) && (ctr < out_len))
        out_buffer[ctr++] = low_noise_bound - t1;

        if(pos >= in_len)
        break;
    }
    return ctr;
}

void small_bounded_noise_generation(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce)
{
    const size_t SEEDBYTES = 32;
    unsigned int i, ctr;
    unsigned char inbuf[SEEDBYTES + 1];
    unsigned char outbuf[2*SHAKE256_RATE];
    uint64_t state[25];

    for(i= 0; i < SEEDBYTES; ++i)
        inbuf[i] = seed[i];
    inbuf[SEEDBYTES] = nonce;

    shake256_absorb(state, inbuf, SEEDBYTES + 1);
    shake256_squeezeblocks(outbuf, 2, state);

    ctr = small_noise_rejection(out_buffer, dilithium_n , outbuf,2*SHAKE256_RATE);
    if(ctr < dilithium_n) {
        shake256_squeezeblocks(outbuf, 1, state);
        small_noise_rejection(out_buffer+ctr, dilithium_n - ctr, outbuf,SHAKE256_RATE);
    }
}


uint32_t large_noise_rejection(uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len)
{
    uint32_t ctr, pos;
    uint32_t t0,t1;

    ctr = pos = 0;
    while(ctr < out_len) {

        t0  = buffer[pos];
        t0 |= (uint32_t)buffer[pos + 1] << 8;
        t0 |= (uint32_t)buffer[pos + 2] << 16;
        t0 &= 0x7FFFF;

        t1  = buffer[pos + 2] >> 4;
        t1 |= (uint32_t)buffer[pos + 3] << 4;
        t1 |= (uint32_t)buffer[pos + 4] << 12;
        t1 &= 0x7FFFF;

        pos += 5;

        if(t0 <= (2*large_noise_bound))
        out_buffer[ctr++] = large_noise_bound - t0;
        if((t1 <= (2*large_noise_bound)) && (ctr < out_len))
        out_buffer[ctr++] = large_noise_bound - t1;

        if(pos >= in_len)
            break;
    }
    return ctr;
}

void large_bounded_noise_generation(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce)
{
    const size_t SEEDBYTES = 32;
    const size_t CRHBYTES  = 48;
    unsigned int i, ctr;
    unsigned char inbuf[SEEDBYTES + CRHBYTES + 2];
    unsigned char outbuf[5*SHAKE256_RATE];
    uint64_t state[25];

    for(i= 0; i < SEEDBYTES + CRHBYTES; ++i)
        inbuf[i] = seed[i];
    inbuf[SEEDBYTES + CRHBYTES + 0] = nonce & 0xFF;
    inbuf[SEEDBYTES + CRHBYTES + 1] = nonce >>   8;

    shake256_absorb(state, inbuf, SEEDBYTES + CRHBYTES + 2);
    shake256_squeezeblocks(outbuf, 5, state);

    ctr = large_noise_rejection(out_buffer, dilithium_n , outbuf,5*SHAKE256_RATE);
    if(ctr < dilithium_n) {
        shake256_squeezeblocks(outbuf, 1, state);
        ctr += large_noise_rejection(out_buffer+ctr, dilithium_n - ctr, outbuf,SHAKE256_RATE);
    }
}

static void poly_mult_schoolbook(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n)
{
    for(uint32_t i = 0; i < n;++i)
    {
        pC[i] = 0;
        for(uint32_t j = 0; j <= i; ++j)
        {
            pC[i] += pA[i-j] * pB[j];
        }
    }

    for(uint32_t i = 0; i < n-1;++i)
    {
        pC[2*n-1-i-1] = 0;
        for(uint32_t j = 0; j <= i; ++j)
        {
            pC[2*n-1-i-1] += pA[n-(i-j)-1] * pB[n-j-1];
        }
    }
}


]void poly_mult_karatsuba(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n, size_t recursions)
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



void poly_binary_mult(uint32_t* pC, unsigned char* pA, uint32_t* pB, size_t n, size_t k)
{
    memset(pC,0,k*n*sizeof(uint32_t));
    for(uint32_t j =0; j < k;++j)
    {
        uint32_t tmp_poly[2*n];
        memset((unsigned char*)tmp_poly,0,2*n*sizeof(uint32_t));
        for(uint32_t i =0; i < n;++i)
        {
            if(pA[i] == 1)
            {
                poly_add(&tmp_poly[i],&pB[j*n],&tmp_poly[i],n);
            }else if(pA[i]==-1)
            {
                poly_sub(&tmp_poly[i],&pB[j*n],&tmp_poly[i],n);
            }
        }
        poly_sub(tmp_poly,tmp_poly,&tmp_poly[n],n);
        poly_add(&pC[j*n],&pC[j*n],tmp_poly,n);
    }
}

#define BLOCKS 3


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
void keygen_power_of_two(uint32_t* pk, uint32_t *sk)
{
    /// Modif
    uint32_t A [A__len],s1[s1_len],s2[s2_len],t[t__len],t1[t__len];
    unsigned char rho[32],rhoprime[32];

    for(uint32_t i = 0; i < 8;++i) ((uint32_t*)rho)[i] = rand_uint32_t();
    sam(A,rho);

    for(uint32_t i = 0; i < 8;++i) ((uint32_t*)rhoprime)[i] = rand_uint32_t();
    unsigned char nonce = 0;
    for(uint32_t i = 0; i < dilithium_l; ++i) small_bounded_noise_generation_256(&s1[i*dilithium_n],rhoprime,nonce++);
    for(uint32_t i = 0; i < dilithium_k; ++i) small_bounded_noise_generation_256(&s2[i*dilithium_n],rhoprime,nonce++);

    /// t = A*s1
    poly_mat_vec_mult_mod_karatsuba(t,A,s1,dilithium_k,dilithium_l,dilithium_n,karatsuba_recursions);

    /// t = t + s2
    poly_add(t,t,s2,t__len);

    for(uint32_t i = 0; i < t__len; ++i) highbits(&t1[i],t[i],dilithium_d);
    pack_pk(pk,rho,t1);
    pack_sk(sk,rho,s1,s2,t);
}

void sign_power_of_two(uint32_t* signature, uint32_t* sk)
{

    uint32_t rounds = 0;
    uint32_t A [A__len];
    uint32_t t [t__len],t0[t__len],t1[t__len];
    uint32_t s1[s1_len],s2[s2_len];
    uint32_t y [y__len],w [w__len],w1[w__len],z  [z__len];
    uint32_t r [r__len],r0[r__len],r1[r__len],ct0[t__len];

    unsigned char rho[32],rhoprime[32+48];
    unsigned char c [c__len],h[t__len];

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

uint32_t verify_power_of_two(uint32_t* signature, uint32_t* pk)
{
    uint32_t A [A__len],t1b[t__len],t1[t__len],z[z__len],w[w__len],w1[w__len],ct1[t__len];
    unsigned char rho[32];
    unsigned char c [c__len],cp[c__len],h[h__len];


    unpack_pk(pk,rho,t1);
    unpack_signature(signature,z,h,c);
    sam(A,rho);
    for(uint32_t i = 0; i < t__len; ++i) t1b[i] = t1[i]<<dilithium_d;

    poly_mat_vec_mult_mod_karatsuba(w,A,z,dilithium_k,dilithium_l,dilithium_n,karatsuba_recursions);
    poly_binary_mult(ct1,c,t1b,dilithium_n,dilithium_k);
    poly_sub(w,w,ct1,w__len);
    for(uint32_t i = 0; i < w__len; ++i) w1[i] = usehint(h[i],w[i],dilithium_gamma);

    H(cp,rho,t1,w1);

    for(uint32_t i = 0; i < c__len ; ++i) if(c[i] != cp[i]) return 1;
    return 0;
}


int test_func()
{
    uint32_t pk[pk_len];
    uint32_t sk[sk_len];
    uint32_t si[signature_len];

    keygen_power_of_two(pk,sk);
    sign_power_of_two(si,sk);

    if(verify_power_of_two(si,pk))
    {
        printf("Signature failed\n");
    }else
    {
        printf("Signature success\n");
    }
    return 0;
    
}



int main(void)
{
    test_func();
    return 0;

}

