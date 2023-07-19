#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
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
#include <arm_neon.h>


#define karatsuba_recursions 4

#define matrix_index(i,j,m,n) (i+j*m)
#define matrix_len(m,n) (m*n)
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#define SEEDBYTES 32
#define CRHBYTES 64

typedef struct {
    /** Internal state. */
    void *ctx;
}OQS_SHA3_shake128_inc_ctx;

#define KECCAK_CTX_ALIGNMENT 32
#def　　NBCMXZjhine _KECCAK_CTX_BYTES (200+sizeof(uint64_t))
#define KECCAK_CTX_BYTES (KECCAK_CTX_ALIGNMENT * \ ((_KECCAK_CTX_BYTES + KECCAK_CTX_ALIGNMENT - 1)/KECCAK_CTX_ALIGNMENT))
static KeccakAddBytesFn *Keccak_AddBytes_ptr = NULL;
static KeccakInitFn *Keccak_Initialize_ptr = &Keccak_Dispatch;

#define vload(ptr) vld1q_u64(ptr);
// ptr <= c;
#define vstore(ptr, c) vst1q_u64(ptr, c);
// c = a ^ b
#define vxor(c, a, b) c = veorq_u64(a, b);

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
#define stream128_init(STATE, SEED, NONCE) \
        dilithium_aes256ctr_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        aes256ctr_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) shake128_inc_ctx_release(STATE)


#define shake256incctx OQS_SHA3_shake256_inc_ctx
#define shake256_inc_init OQS_SHA3_shake256_inc_init
#define shake256_inc_absorb OQS_SHA3_shake256_inc_absorb
#define shake256_inc_finalize OQS_SHA3_shake256_inc_finalize
#define shake256_inc_squeeze OQS_SHA3_shake256_inc_squeeze
#define shake256_inc_ctx_release OQS_SHA3_shake256_inc_ctx_release
#define shake256_inc_ctx_clone OQS_SHA3_shake256_inc_ctx_clone
#define shake256_inc_ctx_reset OQS_SHA3_shake256_inc_ctx_reset

static KeccakInitFn Keccak_Dispatch;
static KeccakInitFn *Keccak_Initialize_ptr = &Keccak_Dispatch;
static KeccakAddByteFn *Keccak_AddByte_ptr = NULL;
static KeccakAddBytesFn *Keccak_AddBytes_ptr = NULL;
static KeccakPermuteFn *Keccak_Permute_ptr = NULL;
static KeccakExtractBytesFn *Keccak_ExtractBytes_ptr = NULL;
static KeccakFastLoopAbsorbFn *Keccak_FastLoopAbsorb_ptr = NULL;

#define shake128_absorb_once OQS_SHA3_shake128_absorb_once
void OQS_SHA3_shake128_absorb_once(shake128incctx *state, const uint8_t *in, size_t inlen);

#define shake256_absorb_once OQS_SHA3_shake256_absorb_once
void OQS_SHA3_shake256_absorb_once(shake256incctx *state, const uint8_t *in, size_t inlen);

#define shake128_squeezeblocks(OUT, NBLOCKS, STATE) \
        OQS_SHA3_shake128_inc_squeeze(OUT, (NBLOCKS)*OQS_SHA3_SHAKE128_RATE, STATE)

#define shake256_squeezeblocks(OUT, NBLOCKS, STATE) \
        OQS_SHA3_shake256_inc_squeeze(OUT, (NBLOCKS)*OQS_SHA3_SHAKE256_RATE, STATE)
#define shake128_squeezeblocks(OUT, NBLOCKS, STATE) \
        OQS_SHA3_shake128_inc_squeeze(OUT, (NBLOCKS)*OQS_SHA3_SHAKE128_RATE, STATE)

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
* Name:        lib_mask_keygen
*
* Description: 鍵生成
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int lib_mask_keygen(uint8_t *pk, uint8_t *sk) {
    

    
  uint8_t seedbuf[2*SEEDBYTES + CRHBYTES];
  uint8_t tr[SEEDBYTES];
  uint8_t rho[2*SEEDBYTES + CRHBYTES],rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /*ランダムな rho, rhoprime and key を得る*/
  randombytes(seedbuf,SEEDBYTES);
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

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    ctx s;
    init(&s);
    OQS_SHA3_shake256_inc_absorb(&s, input, inlen);
    OQS_SHA3_shake256_inc_finalize(&s);
    OQS_SHA3_shake256_inc_squeeze(output, outlen, &s);
    OQS_SHA3_shake256_inc_ctx_release(&s);
}

void init(ctx *state) {
    state->ctx = OQS_MEM_aligned_alloc(KECCAK_CTX_ALIGNMENT, KECCAK_CTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_reset((uint64_t *)state->ctx);
}


/*
・aligned_alloc: aligned_allocはC11で導入された関数で、glibcなどのいくつかの実装でサポートされています。指定されたアラインメントでメモリを割り当てます。
・posix_memalign: posix_memalignはPOSIX仕様に含まれる関数で、指定されたアラインメントでメモリを割り当てます。
・memalign: いくつかのシステムではmemalignが利用可能で、指定されたアラインメントでメモリを割り当てます。
・__mingw_aligned_malloc: MinGW（Minimalist GNU for Windows）環境の場合に、指定されたアラインメントでメモリを割り当てます。
・_aligned_malloc: Microsoft Visual C++コンパイラ（MSVC）環境の場合に、指定されたアラインメントでメモリを割り当てます。
*/

void *OQS_MEM_aligned_alloc(size_t alignment, size_t size) {
#if defined(OQS_HAVE_ALIGNED_ALLOC) // glibc and other implementations providing aligned_alloc
    return aligned_alloc(alignment, size);
#else
    // Check alignment (power of 2, and >= sizeof(void*)) and size (multiple of alignment)
    if (alignment & (alignment - 1) || size & (alignment - 1) || alignment < sizeof(void *)) {
        errno = EINVAL;
        return NULL;
    }

#if defined(OQS_HAVE_POSIX_MEMALIGN)
    void *ptr = NULL;
    const int err = posix_memalign(&ptr, alignment, size);
    if (err) {
        errno = err;
        ptr = NULL;
    }
    return ptr;
#elif defined(OQS_HAVE_MEMALIGN)
    return memalign(alignment, size);
#elif defined(__MINGW32__) || defined(__MINGW64__)
    return __mingw_aligned_malloc(size, alignment);
#elif defined(_MSC_VER)
    return _aligned_malloc(size, alignment);
#else
    if (!size) {
        return NULL;
    }
    // Overallocate to be able to align the pointer (alignment -1) and to store
    // the difference between the pointer returned to the user (ptr) and the
    // pointer returned by malloc (buffer). The difference is caped to 255 and
    // can be made larger if necessary, but this should be enough for all users
    // in liboqs.
    //
    // buffer      ptr
    // ↓           ↓
    // ...........|...................
    //            |
    //       diff = ptr - buffer
    const size_t offset = alignment - 1 + sizeof(uint8_t);
    uint8_t *buffer = malloc(size + offset);
    if (!buffer) {
        return NULL;
    }

    // Align the pointer returned to the user.
    uint8_t *ptr = (uint8_t *)(((uintptr_t)(buffer) + offset) & ~(alignment - 1));
    ptrdiff_t diff = ptr - buffer;
    if (diff > UINT8_MAX) {
        // This should never happen in our code, but just to be safe
        free(buffer); // IGNORE free-check
        errno = EINVAL;
        return NULL;
    }
    // Store the difference one byte ahead the returned poitner so that free
    // can reconstruct buffer.
    ptr[-1] = diff;
    return ptr;
#endif
#endif
}

void OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb((uint64_t *)state->ctx, OQS_SHA3_SHAKE256_RATE, input, inlen);
}

static void keccak_inc_absorb(uint64_t *s, uint32_t r, const uint8_t *m,
                              size_t mlen) {
    uint64_t c = r - s[25];

    if (s[25] && mlen >= c) {
        (*Keccak_AddBytes_ptr)(s, m, (unsigned int)s[25], (unsigned int)c);
        (*Keccak_Permute_ptr)(s);
        mlen -= c;
        m += c;
        s[25] = 0;
    }

#ifdef KeccakF1600_FastLoop_supported
    if (mlen >= r) {
        c = (*Keccak_FastLoop_Absorb_ptr)(s, r / 8, m, mlen);
        mlen -= c;
        m += c;
    }
#else
    while (mlen >= r) {
        (*Keccak_AddBytes_ptr)(s, m, 0, r);
        (*Keccak_Permute_ptr)(s);
        mlen -= r;
        m += r;
    }
#endif

    (*Keccak_AddBytes_ptr)(s, m, (unsigned int)s[25], (unsigned int)mlen);
    s[25] += mlen;
}

void OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state) {
    keccak_inc_finalize((uint64_t *)state->ctx, OQS_SHA3_SHAKE256_RATE, 0x1F);
}

static void keccak_inc_squeeze(uint8_t *h, size_t outlen,
                               uint64_t *s, uint32_t r) {
    while (outlen > s[25]) {
        (*Keccak_ExtractBytes_ptr)(s, h, (unsigned int)(r - s[25]), (unsigned int)s[25]);
        (*Keccak_Permute_ptr)(s);
        h += s[25];
        outlen -= s[25];
        s[25] = r;
    }
    (*Keccak_ExtractBytes_ptr)(s, h, (unsigned int)(r - s[25]), (unsigned int)outlen);
    s[25] -= outlen;
}


void OQS_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state) {
    keccak_inc_squeeze(output, outlen, state->ctx, OQS_SHA3_SHAKE256_RATE);
}

static void keccak_inc_squeeze(uint8_t *h, size_t outlen,
                               uint64_t *s, uint32_t r) {
    while (outlen > s[25]) {
        (*Keccak_ExtractBytes_ptr)(s, h, (unsigned int)(r - s[25]), (unsigned int)s[25]);
        (*Keccak_Permute_ptr)(s);
        h += s[25];
        outlen -= s[25];
        s[25] = r;
    }
    (*Keccak_ExtractBytes_ptr)(s, h, (unsigned int)(r - s[25]), (unsigned int)outlen);
    s[25] -= outlen;
}

void OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state) {
    OQS_MEM_aligned_free(state->ctx);
}

void OQS_MEM_aligned_free(void *ptr) {
#if defined(OQS_HAVE_ALIGNED_ALLOC) || defined(OQS_HAVE_POSIX_MEMALIGN) || defined(OQS_HAVE_MEMALIGN)
    free(ptr); // IGNORE free-check
#elif defined(__MINGW32__) || defined(__MINGW64__)
    __mingw_aligned_free(ptr);
#elif defined(_MSC_VER)
    _aligned_free(ptr);
#else
    if (ptr) {
        // Reconstruct the pointer returned from malloc using the difference
        // stored one byte ahead of ptr.
        uint8_t *u8ptr = ptr;
        free(u8ptr - u8ptr[-1]); // IGNORE free-check
    }
#endif
}

void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
  unsigned int i, j;

  for(i = 0; i < K; ++i)
    for(j = 0; j < L; ++j)
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

#define POLY_UNIFORM_NBLOCKS ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)
void poly_uniform(poly *a,
                  const uint8_t seed[SEEDBYTES],
                  uint16_t nonce)
{
  unsigned int i, ctr, off;
  unsigned int buflen = POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES + 2];
  stream128_state state;

  stream128_init(&state, seed, nonce);
  stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

  ctr = rej_uniform(a->coeffs, N, buf, buflen);

  while(ctr < N) {
    off = buflen % 3;
    for(i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];

    stream128_squeezeblocks(buf + off, 1, &state);
    buflen = STREAM128_BLOCKBYTES + off;
    ctr += rej_uniform(a->coeffs + ctr, N - ctr, buf, buflen);
  }
  stream128_release(&state);
}



void dilithium_shake128_stream_init(shake128incctx *state, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_inc_init(state);
  shake128_inc_absorb(state, seed, SEEDBYTES);
  shake128_inc_absorb(state, t, 2);
  shake128_inc_finalize(state);
}

void shake128_inc_init(OQS_SHA3_shake128_inc_ctx *state) {
    state->ctx = OQS_MEM_aligned_alloc(KECCAK_CTX_ALIGNMENT, KECCAK_CTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_reset((uint64_t *)state->ctx);
}

static void keccak_inc_reset(uint64_t *s) {
    (*Keccak_Initialize_ptr)(s);
    s[25] = 0;
}

void OQS_SHA3_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb((uint64_t *)state->ctx, OQS_SHA3_SHAKE128_RATE, input, inlen);
}

static void keccak_inc_absorb(uint64_t *s, uint32_t r, const uint8_t *m,
                              size_t mlen) {
    uint64_t c = r - s[25];

    if (s[25] && mlen >= c) {
        (*Keccak_AddBytes_ptr)(s, m, (unsigned int)s[25], (unsigned int)c);
        (*Keccak_Permute_ptr)(s);
        mlen -= c;
        m += c;
        s[25] = 0;
    }

#ifdef KeccakF1600_FastLoop_supported
    if (mlen >= r) {
        c = (*Keccak_FastLoop_Absorb_ptr)(s, r / 8, m, mlen);
        mlen -= c;
        m += c;
    }
#else
    while (mlen >= r) {
        (*Keccak_AddBytes_ptr)(s, m, 0, r);
        (*Keccak_Permute_ptr)(s);
        mlen -= r;
        m += r;
    }
#endif

    (*Keccak_AddBytes_ptr)(s, m, (unsigned int)s[25], (unsigned int)mlen);
    s[25] += mlen;
}

void OQS_SHA3_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state) {
    keccak_inc_finalize((uint64_t *)state->ctx, OQS_SHA3_SHAKE128_RATE, 0x1F);
}

static void keccak_inc_finalize(uint64_t *s, uint32_t r, uint8_t p) {
    /* After keccak_inc_absorb, we are guaranteed that s[25] < r,
       so we can always use one more byte for p in the current state. */
    (*Keccak_AddByte_ptr)(s, p, (unsigned int)s[25]);
    (*Keccak_AddByte_ptr)(s, 0x80, (unsigned int)(r - 1));
    s[25] = 0;
}

void OQS_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state) {
    keccak_inc_squeeze(output, outlen, (uint64_t *)state->ctx, OQS_SHA3_SHAKE128_RATE);
}

static void keccak_inc_squeeze(uint8_t *h, size_t outlen,
                               uint64_t *s, uint32_t r) {
    while (outlen > s[25]) {
        (*Keccak_ExtractBytes_ptr)(s, h, (unsigned int)(r - s[25]), (unsigned int)s[25]);
        (*Keccak_Permute_ptr)(s);
        h += s[25];
        outlen -= s[25];
        s[25] = r;
    }
    (*Keccak_ExtractBytes_ptr)(s, h, (unsigned int)(r - s[25]), (unsigned int)outlen);
    s[25] -= outlen;
}

static unsigned int rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t;
  DBENCH_START();

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if(t < Q)
      a[ctr++] = t;
  }

  DBENCH_STOP(*tsample);
  return ctr;
}

void OQS_SHA3_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state) {
    OQS_MEM_aligned_free(state->ctx);
}

oid polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void poly_uniform_eta(poly *a,
                      const uint8_t seed[CRHBYTES],
                      uint16_t nonce)
{
  unsigned int ctr;
  unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES;
  uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS*STREAM256_BLOCKBYTES];
  stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);

  ctr = rej_eta(a->coeffs, N, buf, buflen);

  while(ctr < N) {
    stream256_squeezeblocks(buf, 1, &state);
    ctr += rej_eta(a->coeffs + ctr, N - ctr, buf, STREAM256_BLOCKBYTES);
  }
  stream256_release(&state);
}
