#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
/*#include "randombytes.h"*/
#include "symmetric.h"
/*#include "fips202.h"*/
#include "rounding.h"
#include "karatsuba.h"
#include "noise.h"
#include "rejection.h"
#include "hash.h"

#define karatsuba_recursions 4

#define matrix_index(i,j,m,n) (i+j*m)
#define matrix_len(m,n) (m*n)
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H


//ここから下は追加ヘッダー

#include <oqs/rand.h>

#define randombytes OQS_randombytes

#endif
// SPDX-License-Identifier: MIT

#ifndef FIPS202_H
#define FIPS202_H

#include <oqs/sha3.h>

#define SHAKE128_RATE OQS_SHA3_SHAKE128_RATE
#define shake128 OQS_SHA3_shake128

#define SHAKE256_RATE OQS_SHA3_SHAKE256_RATE
#define shake256 OQS_SHA3_shake256

#define SHA3_256_RATE OQS_SHA3_SHA3_256_RATE
#define sha3_256 OQS_SHA3_sha3_256
#define sha3_256_inc_init OQS_SHA3_sha3_256_inc_init
#define sha3_256_inc_absorb OQS_SHA3_sha3_256_inc_absorb
#define sha3_256_inc_finalize OQS_SHA3_sha3_256_inc_finalize
#define sha3_256_inc_ctx_clone OQS_SHA3_sha3_256_inc_ctx_clone
#define sha3_256_inc_ctx_release OQS_SHA3_sha3_256_inc_ctx_release

#define SHA3_384_RATE OQS_SHA3_SHA3_384_RATE
#define sha3_384 OQS_SHA3_sha3_384
#define sha3_384_inc_init OQS_SHA3_sha3_384_inc_init
#define sha3_384_inc_absorb OQS_SHA3_sha3_384_inc_absorb
#define sha3_384_inc_finalize OQS_SHA3_sha3_384_inc_finalize
#define sha3_384_inc_ctx_clone OQS_SHA3_sha3_384_inc_ctx_clone
#define sha3_384_inc_ctx_release OQS_SHA3_sha3_384_inc_ctx_release

#define SHA3_512_RATE OQS_SHA3_SHA3_512_RATE
#define sha3_512 OQS_SHA3_sha3_512
#define sha3_512_inc_init OQS_SHA3_sha3_512_inc_init
#define sha3_512_inc_absorb OQS_SHA3_sha3_512_inc_absorb
#define sha3_512_inc_finalize OQS_SHA3_sha3_512_inc_finalize
#define sha3_512_inc_ctx_clone OQS_SHA3_sha3_512_inc_ctx_clone
#define sha3_512_inc_ctx_release OQS_SHA3_sha3_512_inc_ctx_release

#define shake128incctx OQS_SHA3_shake128_inc_ctx
#define shake128_inc_init OQS_SHA3_shake128_inc_init
#define shake128_inc_absorb OQS_SHA3_shake128_inc_absorb
#define shake128_inc_finalize OQS_SHA3_shake128_inc_finalize
#define shake128_inc_squeeze OQS_SHA3_shake128_inc_squeeze
#define shake128_inc_ctx_release OQS_SHA3_shake128_inc_ctx_release
#define shake128_inc_ctx_clone OQS_SHA3_shake128_inc_ctx_clone
#define shake128_inc_ctx_reset OQS_SHA3_shake128_inc_ctx_reset

#define shake256incctx OQS_SHA3_shake256_inc_ctx
#define shake256_inc_init OQS_SHA3_shake256_inc_init
#define shake256_inc_absorb OQS_SHA3_shake256_inc_absorb
#define shake256_inc_finalize OQS_SHA3_shake256_inc_finalize
#define shake256_inc_squeeze OQS_SHA3_shake256_inc_squeeze
#define shake256_inc_ctx_release OQS_SHA3_shake256_inc_ctx_release
#define shake256_inc_ctx_clone OQS_SHA3_shake256_inc_ctx_clone
#define shake256_inc_ctx_reset OQS_SHA3_shake256_inc_ctx_reset

#define shake128_absorb_once OQS_SHA3_shake128_absorb_once
void OQS_SHA3_shake128_absorb_once(shake128incctx *state, const uint8_t *in, size_t inlen);

#define shake256_absorb_once OQS_SHA3_shake256_absorb_once
void OQS_SHA3_shake256_absorb_once(shake256incctx *state, const uint8_t *in, size_t inlen);

#define shake128_squeezeblocks(OUT, NBLOCKS, STATE) \
        OQS_SHA3_shake128_inc_squeeze(OUT, (NBLOCKS)*OQS_SHA3_SHAKE128_RATE, STATE)

#define shake256_squeezeblocks(OUT, NBLOCKS, STATE) \
        OQS_SHA3_shake256_inc_squeeze(OUT, (NBLOCKS)*OQS_SHA3_SHAKE256_RATE, STATE)

#endif

//  SPDX-License-Identifier: MIT

/*#include "fips202.h"*/

void shake128_absorb_once(shake128incctx *state, const uint8_t *in, size_t inlen) {
    shake128_inc_ctx_reset(state);
    shake128_inc_absorb(state, in, inlen);
    shake128_inc_finalize(state);
}

void shake256_absorb_once(shake256incctx *state, const uint8_t *in, size_t inlen) {
    shake256_inc_ctx_reset(state);
    shake256_inc_absorb(state, in, inlen);
    shake256_inc_finalize(state);
}

//追加ヘッダーここまで


/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  uint8_t tr[SEEDBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  randombytes(seedbuf, SEEDBYTES);
  shake256(seedbuf, 2*SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[3*SEEDBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  shake256incctx state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, tr, SEEDBYTES);
  shake256_inc_absorb(&state, m, mlen);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_inc_ctx_reset(&state);
  shake256_inc_absorb(&state, mu, CRHBYTES);
  shake256_inc_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(sig, SEEDBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  shake256_inc_ctx_release(&state);

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;
  return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  *smlen += mlen;
  return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  shake256incctx state;

  if(siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(H(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, SEEDBYTES);
  shake256_inc_absorb(&state, m, mlen);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_inc_ctx_reset(&state);
  shake256_inc_absorb(&state, mu, CRHBYTES);
  shake256_inc_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(c2, SEEDBYTES, &state);
  shake256_inc_ctx_release(&state);
  for(i = 0; i < SEEDBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
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
