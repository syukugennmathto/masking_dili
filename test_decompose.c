#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#define SHAKE128_RATE 168
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))
#define NROUNDS 24
#define BLOCKS 3
#define Q 8380417
#define GAMMA2 ((Q-1)/88)


typedef struct {
  int32_t coeffs[dilithium_n];
} poly;

typedef struct {
  poly vec[dilithium_l];
} polyvecl;

typedef struct {
    poly vec[dilithium_k];
} polyveck;



void mask_decompose(uint32_t *r1, uint32_t *r0, uint32_t  r , uint32_t base);
void mask2_decompose(uint32_t *r1, uint32_t *r0, uint32_t  r , uint32_t base);
int32_t decompose(int32_t a0, int32_t a);
void polyveck_decompose(int32_t a1,int32_t a0,int32_t a);
void poly_decompose(int32_t a1, int32_t a0,int32_t a);

int main(void)
{
    uint32_t rounds = 0;
    int32_t t_len = 3;
    int32_t s_len = 3;
    
    int32_t dilithium_N =3;
    int32_t dilithium_K = 1;
    uint32_t A [A__len];
    uint32_t t [t_len],t0[t_len],t1[t_len];
    uint32_t s[s_len],s0[s_len],s1[s_len];
    uint32_t r [r__len],r0[r__len],r1[r__len],ct0[t__len];
    int32_t w0[dilithium_N][dilithium_K],w1[dilithium_N][dilithium_K];
    

    for(uint32_t i = 0; i < t_len; ++i) printf("%d,",t[i]);
    printf("\n");
    for(uint32_t i = 0; i < t_len; ++i)
        {
            mask_decompose(&t1[i],&t0[i],t[i],dilithium_d);
            printf("%d,",t1[i]);
        }
        printf("\n");

    for(uint32_t i = 0; i < dilithium_N; ++i) for(uint32_t  j= 0; j < dilithium_K; ++j) polyveck_decompose(w1[i][j], w0[i][j], w1[i][j]);
    for(uint32_t i = 0; i < dilithium_N; ++i) for(uint32_t j = 0; j < dilithium_K; ++j) printf("%d,",w1[i][j]);
    printf("\n");
    
}



void mask_decompose(uint32_t *a0, uint32_t *r0, uint32_t  a, uint32_t base)
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
void mask2_decompose(uint32_t *a0, uint32_t *r0, uint32_t  a, uint32_t base)
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
void polyveck_decompose(int32_t a1,int32_t a0,int32_t a)
{
    poly_decompose(a1, a0, a);
    
}

void poly_decompose(int32_t a1, int32_t a0,int32_t a) {
  unsigned int i;

  a1 = decompose(a0, a);
}

int32_t decompose(int32_t a0, int32_t a)
{
  int32_t a1;

  a1  = (a + 127) >> 7;
  a1  = (a1*11275 + (1 << 23)) >> 24;
  a1 ^= ((43 - a1) >> 31) & a1;
  a0  = a - a1*2*GAMMA2;
  a0 -= (((Q-1)/2 - a0) >> 31) & Q;
  return a1;
}
