#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>

/*#include "params.h"*/
/*#include "sign.h"*/
/*#include "packing.h"*/
/*#include "polyvec.h"*/
/*#include "poly.h"*/
/*#include "randombytes.h"*/
/*#include "symmetric.h"*/
/*#include "fips202.h"*/
/*#include "rounding.h"*/
/*#include "karatsuba.h"*/
/*#include "noise.h"*/
/*#include "rejection.h"*/
/*#include "hash.h"*/
/*#include "config.h"*/
#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#define strcasecmp _stricmp
#else
#include <unistd.h>
#include <strings.h>
#if defined(__APPLE__)
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
#include <Security/SecRandom.h>
#else
#include <sys/random.h>
#endif
#else
#include <unistd.h>
#endif
#endif
#include <fcntl.h>
#include <stdlib.h>


#if !defined(_WIN32) && !defined(OQS_HAVE_EXPLICIT_BZERO)
// Request memset_s
#define __STDC_WANT_LIB_EXT1__ 1
#endif


#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Macro for terminating the program if x is
 * a null pointer.
 */
#define OQS_EXIT_IF_NULLPTR(x)  \
    do {                        \
        if ( (x) == (void*)0 )  \
            exit(EXIT_FAILURE); \
    } while (0)

/**
 * This macro is intended to replace those assert()s
 * involving side-effecting statements in aes/aes_ossl.c.
 *
 * assert() becomes a no-op when -DNDEBUG is defined,
 * which causes compilation failures when the statement
 * being checked also results in side-effects.
 *
 * This is a temporary workaround until a better error
 * handling strategy is developed.
 */
#define OQS_OPENSSL_GUARD(x)    \
    do {                        \
        if( 1 != (x) ) {        \
            exit(EXIT_FAILURE); \
        }                       \
    } while (0)

/**
 * Certain functions (such as OQS_randombytes_openssl in
 * src/rand/rand.c) take in a size_t parameter, but can
 * only handle values up to INT_MAX for those parameters.
 * This macro is a temporary workaround for such functions.
 */
#define SIZE_T_TO_INT_OR_EXIT(size_t_var_name, int_var_name)  \
    int int_var_name = 0;                                     \
    if (size_t_var_name <= INT_MAX) {                         \
        int_var_name = (int)size_t_var_name;                  \
    } else {                                                  \
        exit(EXIT_FAILURE);                                   \
    }

/**
 * Defines which functions should be exposed outside the LibOQS library
 *
 * By default the visibility of all the symbols is defined to "hidden"
 * Only the library API should be marked as default
 *
 * Example: OQS_API return_value function_name(void);
 */
#if defined(_WIN32)
#define OQS_API __declspec(dllexport)
#else
#define OQS_API __attribute__((visibility("default")))
#endif

#if defined(OQS_SYS_UEFI)
#undef OQS_API
#define OQS_API
#endif

/**
 * Represents return values from functions.
 *
 * Callers should compare with the symbol rather than the individual value.
 * For example,
 *
 *     ret = OQS_KEM_encaps(...);
 *     if (ret == OQS_SUCCESS) { ... }
 *
 * rather than
 *
 *     if (!OQS_KEM_encaps(...) { ... }
 *
 */
typedef enum {
    /** Used to indicate that some undefined error occurred. */
    OQS_ERROR = -1,
    /** Used to indicate successful return from function. */
    OQS_SUCCESS = 0,
    /** Used to indicate failures in external libraries (e.g., OpenSSL). */
    OQS_EXTERNAL_LIB_ERROR_OPENSSL = 50,
} OQS_STATUS;

/**
 * CPU runtime detection flags
 */
typedef enum {
    OQS_CPU_EXT_INIT, /* Must be first */
    /* Start extension list */
    OQS_CPU_EXT_ADX,
    OQS_CPU_EXT_AES,
    OQS_CPU_EXT_AVX,
    OQS_CPU_EXT_AVX2,
    OQS_CPU_EXT_AVX512,
    OQS_CPU_EXT_BMI1,
    OQS_CPU_EXT_BMI2,
    OQS_CPU_EXT_PCLMULQDQ,
    OQS_CPU_EXT_VPCLMULQDQ,
    OQS_CPU_EXT_POPCNT,
    OQS_CPU_EXT_SSE,
    OQS_CPU_EXT_SSE2,
    OQS_CPU_EXT_SSE3,
    OQS_CPU_EXT_ARM_AES,
    OQS_CPU_EXT_ARM_SHA2,
    OQS_CPU_EXT_ARM_SHA3,
    OQS_CPU_EXT_ARM_NEON,
    /* End extension list */
    OQS_CPU_EXT_COUNT, /* Must be last */
} OQS_CPU_EXT;

/**
 * Checks if the CPU supports a given extension
 *
 * \return 1 if the given CPU extension is available, 0 otherwise.
 */
OQS_API int OQS_CPU_has_extension(OQS_CPU_EXT ext);

/**
 * This currently only sets the values in the OQS_CPU_EXTENSIONS,
 * and so has effect only when OQS_DIST_BUILD is set.
 */
OQS_API void OQS_init(void);

/**
 * Return library version string.
 */
OQS_API const char *OQS_version(void);

/**
 * Constant time comparison of byte sequences `a` and `b` of length `len`.
 * Returns 0 if the byte sequences are equal or if `len`=0.
 * Returns 1 otherwise.
 *
 * @param[in] a A byte sequence of length at least `len`.
 * @param[in] b A byte sequence of length at least `len`.
 * @param[in] len The number of bytes to compare.
 */
OQS_API int OQS_MEM_secure_bcmp(const void *a, const void *b, size_t len);

/**
 * Zeros out `len` bytes of memory starting at `ptr`.
 *
 * Designed to be protected against optimizing compilers which try to remove
 * "unnecessary" operations.  Should be used for all buffers containing secret
 * data.
 *
 * @param[in] ptr The start of the memory to zero out.
 * @param[in] len The number of bytes to zero out.
 */
OQS_API void OQS_MEM_cleanse(void *ptr, size_t len);

/**
 * Zeros out `len` bytes of memory starting at `ptr`, then frees `ptr`.
 *
 * Can be called with `ptr = NULL`, in which case no operation is performed.
 *
 * Designed to be protected against optimizing compilers which try to remove
 * "unnecessary" operations.  Should be used for all buffers containing secret
 * data.
 *
 * @param[in] ptr The start of the memory to zero out and free.
 * @param[in] len The number of bytes to zero out.
 */
OQS_API void OQS_MEM_secure_free(void *ptr, size_t len);

/**
 * Frees `ptr`.
 *
 * Can be called with `ptr = NULL`, in which case no operation is performed.
 *
 * Should only be used on non-secret data.
 *
 * @param[in] ptr The start of the memory to free.
 */
OQS_API void OQS_MEM_insecure_free(void *ptr);

/**
 * Internal implementation of C11 aligned_alloc to work around compiler quirks.
 *
 * Allocates size bytes of uninitialized memory with a base pointer that is
 * a multiple of alignment. Alignment must be a power of two and a multiple
 * of sizeof(void *). Size must be a multiple of alignment.
 */
void *OQS_MEM_aligned_alloc(size_t alignment, size_t size);

/**
 * Free memory allocated with OQS_MEM_aligned_alloc.
 */
void OQS_MEM_aligned_free(void *ptr);

#if defined(__cplusplus)
} // extern "C"
#endif



#ifdef USE_RDPMC  /* Needs echo 2 > /sys/devices/cpu/rdpmc */

static inline uint64_t cpucycles(void) {
  const uint32_t ecx = (1U << 30) + 1;
  uint64_t result;

  __asm__ volatile ("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : "c" (ecx) : "rdx");

  return result;
}

#else

static inline uint64_t cpucycles(void) {
  uint64_t result;

  __asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rdx");

  return result;
}

#endif

uint64_t cpucycles_overhead(void);


#define MONT -4186625 // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

#define montgomery_reduce DILITHIUM_NAMESPACE(montgomery_reduce)
int32_t montgomery_reduce(int64_t a);

#define reduce32 DILITHIUM_NAMESPACE(reduce32)
int32_t reduce32(int32_t a);

#define caddq DILITHIUM_NAMESPACE(caddq)
int32_t caddq(int32_t a);

#define freeze DILITHIUM_NAMESPACE(freeze)
int32_t freeze(int32_t a);

#define BLOCKS 3
#define karatsuba_recursions 4

#define matrix_index(i,j,m,n) (i+j*m)
#define matrix_len(m,n) (m*n)
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H


#ifndef DILITHIUM_MODE
#define DILITHIUM_MODE 2
#endif

#ifdef DILITHIUM_USE_AES
#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2-AES"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium2aes_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium2aes_ref_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3-AES"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium3aes_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium3aes_ref_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5-AES"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium5aes_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium5aes_ref_##s
#endif
#else
#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium2_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium2_ref_##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium3_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium3_ref_##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACETOP pqcrystals_dilithium5_ref
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium5_ref_##s
#endif
#endif



//ここから下は追加ヘッダー
/* #if defined(__cplusplus)
extern "C" {
#endif */

void PQCLEAN_MCELIECE6960119F_VEC_aes256ctr(
    uint8_t *out,
    size_t outlen,
    const uint8_t nonce[AESCTR_NONCEBYTES],
    const uint8_t key[AES256_KEYBYTES]
);


#define ntt DILITHIUM_NAMESPACE(poly_mult_ntt)
void poly_mult_ntt(int32_t c[N], int32_t a[N], int32_t b[N]);

#define ntt DILITHIUM_NAMESPACE(ntt)
void ntt(int32_t a[N]);

#define invntt_tomont DILITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[N]);

typedef void KeccakInitFn(void *);
extern KeccakInitFn \
KeccakP1600_Initialize, \
KeccakP1600_Initialize_plain64, \
KeccakP1600_Initialize_avx2;

typedef void KeccakAddByteFn(void *, const uint8_t, unsigned int);
extern KeccakAddByteFn \
KeccakP1600_AddByte, \
KeccakP1600_AddByte_plain64, \
KeccakP1600_AddByte_avx2;

typedef void KeccakAddBytesFn(void *, const uint8_t *, unsigned int, unsigned int);
extern KeccakAddBytesFn \
KeccakP1600_AddBytes, \
KeccakP1600_AddBytes_plain64, \
KeccakP1600_AddBytes_avx2;

typedef void KeccakPermuteFn(void *);
extern KeccakPermuteFn \
KeccakP1600_Permute_24rounds, \
KeccakP1600_Permute_24rounds_plain64, \
KeccakP1600_Permute_24rounds_avx2;

typedef void KeccakExtractBytesFn(const void *, uint8_t *, unsigned int, unsigned int);
extern KeccakExtractBytesFn \
KeccakP1600_ExtractBytes, \
KeccakP1600_ExtractBytes_plain64, \
KeccakP1600_ExtractBytes_avx2;

typedef size_t KeccakFastLoopAbsorbFn(void *, unsigned int, const uint8_t *, size_t);
extern KeccakFastLoopAbsorbFn \
KeccakF1600_FastLoop_Absorb, \
KeccakF1600_FastLoop_Absorb_plain64, \
KeccakF1600_FastLoop_Absorb_avx2;

typedef void KeccakX4InitFn(void *);
extern KeccakX4InitFn \
KeccakP1600times4_InitializeAll, \
KeccakP1600times4_InitializeAll_serial, \
KeccakP1600times4_InitializeAll_avx2;

typedef void KeccakX4AddByteFn(void *, unsigned int, unsigned char, unsigned int);
extern KeccakX4AddByteFn \
KeccakP1600times4_AddByte, \
KeccakP1600times4_AddByte_serial, \
KeccakP1600times4_AddByte_avx2;

typedef void KeccakX4AddBytesFn(void *, unsigned int, const unsigned char *, unsigned int, unsigned int);
extern KeccakX4AddBytesFn \
KeccakP1600times4_AddBytes, \
KeccakP1600times4_AddBytes_serial, \
KeccakP1600times4_AddBytes_avx2;

typedef void KeccakX4PermuteFn(void *);
extern KeccakX4PermuteFn \
KeccakP1600times4_PermuteAll_24rounds, \
KeccakP1600times4_PermuteAll_24rounds_serial, \
KeccakP1600times4_PermuteAll_24rounds_avx2;

typedef void KeccakX4ExtractBytesFn(const void *, unsigned int, unsigned char *, unsigned int, unsigned int);
extern KeccakX4ExtractBytesFn \
KeccakP1600times4_ExtractBytes, \
KeccakP1600times4_ExtractBytes_serial, \
KeccakP1600times4_ExtractBytes_avx2;



#if defined(__cplusplus)
extern "C" {
#endif

/** Algorithm identifier for system PRNG. */
#define OQS_RAND_alg_system "system"
/** Algorithm identifier for NIST deterministic RNG for KATs. */
#define OQS_RAND_alg_nist_kat "NIST-KAT"
/** Algorithm identifier for using OpenSSL's PRNG. */
#define OQS_RAND_alg_openssl "OpenSSL"

/**
 * Switches OQS_randombytes to use the specified algorithm.
 *
 * @param[in] algorithm The name of the algorithm to use.
 * @return OQS_SUCCESS if `algorithm` is a supported algorithm name, OQS_ERROR otherwise.
 */
OQS_API OQS_STATUS OQS_randombytes_switch_algorithm(const char *algorithm);

/**
 * Switches OQS_randombytes to use the given function.
 *
 * This allows additional custom RNGs besides the provided ones.  The provided RNG
 * function must have the same signature as `OQS_randombytes`.
 *
 * @param[in] algorithm_ptr Pointer to the RNG function to use.
 */
OQS_API void OQS_randombytes_custom_algorithm(void (*algorithm_ptr)(uint8_t *, size_t));

/**
 * Fills the given memory with the requested number of (pseudo)random bytes.
 *
 * This implementation uses whichever algorithm has been selected by
 * OQS_randombytes_switch_algorithm. The default is OQS_randombytes_system, which
 * reads bytes directly from `/dev/urandom`.
 *
 * The caller is responsible for providing a buffer allocated with sufficient room.
 *
 * @param[out] random_array Pointer to the memory to fill with (pseudo)random bytes
 * @param[in] bytes_to_read The number of random bytes to read into memory
 */
OQS_API void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read);

/**
 * Initializes the NIST DRBG with a given seed and with 256-bit security.
 *
 * @param[in] entropy_input The seed; must be exactly 48 bytes
 * @param[in] personalization_string An optional personalization string;
 * may be NULL; if not NULL, must be at least 48 bytes long
 */
OQS_API void OQS_randombytes_nist_kat_init_256bit(const uint8_t *entropy_input, const uint8_t *personalization_string);

#if defined(__cplusplus)
} // extern "C"
#endif


uint32_t rejection(uint32_t* poly, size_t len, size_t bound);

    
/* SHA3 */
/** The SHA-256 byte absorption rate */
#define OQS_SHA3_SHA3_256_RATE 136

/**
 * \brief Process a message with SHA3-256 and return the digest in the output byte array.
 *
 * \warning The output array must be at least 32 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the incremental SHA3-256 API. */
typedef struct {
    /** Internal state. */
    void *ctx;
} OQS_SHA3_sha3_256_inc_ctx;

/**
 * \brief Initialize the state for the incremental SHA3-256 API.
 *
 * \warning Caller is responsible for releasing state by calling
 * OQS_SHA3_sha3_256_inc_ctx_release.
 *
 * \param state The function state to be allocated and initialized.
 */
void OQS_SHA3_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx *state);

/**
 * \brief The SHA3-256 absorb function.
 * Absorb an input into the state.
 *
 * \param state The function state; must be initialized
 * \param input The input array
 * \param inlen The length of the input
 */
void OQS_SHA3_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHA3-256 finalize-and-squeeze function.
 * Finalizes the state and squeezes a 32 byte digest.
 *
 * \warning Output array must be at least 32 bytes.
 * State cannot be used after this without calling OQS_SHA3_sha3_256_inc_reset.
 *
 * \param output The output byte array
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_256_inc_finalize(uint8_t *output, OQS_SHA3_sha3_256_inc_ctx *state);

/**
 * \brief Release the state for the SHA3-256 incremental API.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx *state);

/**
 * \brief Resets the state for the SHA3-256 incremental API.
 * Alternative to freeing and reinitializing the state.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_256_inc_ctx_reset(OQS_SHA3_sha3_256_inc_ctx *state);

/**
 * \brief Clone the state for the SHA3-256 incremental API.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA3_sha3_256_inc_ctx_clone(OQS_SHA3_sha3_256_inc_ctx *dest, const OQS_SHA3_sha3_256_inc_ctx *src);

/** The SHA-384 byte absorption rate */
#define OQS_SHA3_SHA3_384_RATE 104

/**
 * \brief Process a message with SHA3-384 and return the digest in the output byte array.
 *
 * \warning The output array must be at least 48 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA3_sha3_384(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the incremental SHA3-384 API. */
typedef struct {
    /** Internal state. */
    void *ctx;
} OQS_SHA3_sha3_384_inc_ctx;

/**
 * \brief Initialize the state for the incremental SHA3-384 API.
 *
 * \warning Caller is responsible for releasing state by calling
 * OQS_SHA3_sha3_384_inc_ctx_release.
 *
 * \param state The function state to be allocated and initialized.
 */
void OQS_SHA3_sha3_384_inc_init(OQS_SHA3_sha3_384_inc_ctx *state);

/**
 * \brief The SHA3-384 absorb function.
 * Absorb an input into the state.
 *
 * \param state The function state; must be initialized
 * \param input The input array
 * \param inlen The length of the input
 */
void OQS_SHA3_sha3_384_inc_absorb(OQS_SHA3_sha3_384_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHA3-384 finalize-and-squeeze function.
 * Finalizes the state and squeezes a 48 byte digest.
 *
 * \warning Output array must be at least 48 bytes.
 * State cannot be used after this without calling OQS_SHA3_sha3_384_inc_reset.
 *
 * \param output The output byte array
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_384_inc_finalize(uint8_t *output, OQS_SHA3_sha3_384_inc_ctx *state);

/**
 * \brief Release the state for the SHA3-384 incremental API.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_384_inc_ctx_release(OQS_SHA3_sha3_384_inc_ctx *state);

/**
 * \brief Resets the state for the SHA3-384 incremental API.
 * Alternative to freeing and reinitializing the state.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_384_inc_ctx_reset(OQS_SHA3_sha3_384_inc_ctx *state);

/**
 * \brief Clone the state for the SHA3-384 incremental API.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA3_sha3_384_inc_ctx_clone(OQS_SHA3_sha3_384_inc_ctx *dest, const OQS_SHA3_sha3_384_inc_ctx *src);

/** The SHA-512 byte absorption rate */
#define OQS_SHA3_SHA3_512_RATE 72

/**
 * \brief Process a message with SHA3-512 and return the digest in the output byte array.
 *
 * \warning The output array must be at least 64 bytes in length.
 *
 * \param output The output byte array
 * \param input The message input byte array
 * \param inplen The number of message bytes to process
 */
void OQS_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inplen);

/** Data structure for the state of the incremental SHA3-512 API. */
typedef struct {
    /** Internal state. */
    void *ctx;
} OQS_SHA3_sha3_512_inc_ctx;

/**
 * \brief Initialize the state for the incremental SHA3-512 API.
 *
 * \warning Caller is responsible for releasing state by calling
 * OQS_SHA3_sha3_512_inc_ctx_release.
 *
 * \param state The function state to be allocated and initialized.
 */
void OQS_SHA3_sha3_512_inc_init(OQS_SHA3_sha3_512_inc_ctx *state);

/**
 * \brief The SHA3-512 absorb function.
 * Absorb an input into the state.
 *
 * \param state The function state; must be initialized
 * \param input The input array
 * \param inlen The length of the input
 */
void OQS_SHA3_sha3_512_inc_absorb(OQS_SHA3_sha3_512_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHA3-512 finalize-and-squeeze function.
 * Finalizes the state and squeezes a 64 byte digest.
 *
 * \warning Output array must be at least 64 bytes.
 * State cannot be used after this without calling OQS_SHA3_sha3_512_inc_reset.
 *
 * \param output The output byte array
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_512_inc_finalize(uint8_t *output, OQS_SHA3_sha3_512_inc_ctx *state);

/**
 * \brief Release the state for the SHA3-512 incremental API.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_512_inc_ctx_release(OQS_SHA3_sha3_512_inc_ctx *state);

/**
 * \brief Resets the state for the SHA3-512 incremental API.
 * Alternative to freeing and reinitializing the state.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_sha3_512_inc_ctx_reset(OQS_SHA3_sha3_512_inc_ctx *state);

/**
 * \brief Clone the state for the SHA3-512 incremental API.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA3_sha3_512_inc_ctx_clone(OQS_SHA3_sha3_512_inc_ctx *dest, const OQS_SHA3_sha3_512_inc_ctx *src);

/* SHAKE */

/** The SHAKE-128 byte absorption rate */
#define OQS_SHA3_SHAKE128_RATE 168

/**
 * \brief Seed a SHAKE-128 instance, and generate an array of pseudo-random bytes.
 *
 * \warning The output array length must not be zero.
 *
 * \param output The output byte array
 * \param outlen The number of output bytes to generate
 * \param input The input seed byte array
 * \param inplen The number of seed bytes to process
 */
void OQS_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);

/** Data structure for the state of the incremental SHAKE-128 API. */
typedef struct {
    /** Internal state. */
    void *ctx;
} OQS_SHA3_shake128_inc_ctx;

/**
 * \brief Initialize the state for the incremental SHAKE-128 API.
 *
 * \warning Caller is responsible for releasing state by calling
 * OQS_SHA3_shake128_inc_ctx_release.
 *
 * \param state The function state to be initialized; must be allocated
 */
void OQS_SHA3_shake128_inc_init(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief The SHAKE-128 absorb function.
 * Absorb an input into the state.
 *
 * \warning State must be initialized.
 *
 * \param state The function state; must be initialized
 * \param input input buffer
 * \param inlen length of input buffer
 */
void OQS_SHA3_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHAKE-128 finalize function.
 * Prepares the state for squeezing.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief The SHAKE-128 squeeze function.
 * Extracts to an output byte array.
 *
 * \param output output buffer
 * \param outlen bytes of outbut buffer
 * \param state The function state; must be initialized and finalized
 */
void OQS_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief Frees the state for the incremental SHAKE-128 API.
 *
 * \param state The state to free
 */
void OQS_SHA3_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state);

/**
 * \brief Copies the state for the SHAKE-128 incremental API.
 *
 * \warning Caller is responsible for releasing dest by calling
 * OQS_SHA3_shake128_inc_ctx_release.
 *
 * \param dest The function state to copy into; must be initialized
 * \param src The function state to copy; must be initialized
 */
void OQS_SHA3_shake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx *dest, const OQS_SHA3_shake128_inc_ctx *src);

/**
 * \brief Resets the state for the SHAKE-128 incremental API. Allows a context
 * to be re-used without free and init calls.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake128_inc_ctx_reset(OQS_SHA3_shake128_inc_ctx *state);

/** The SHAKE-256 byte absorption rate */
#define OQS_SHA3_SHAKE256_RATE 136

/**
 * \brief Seed a SHAKE-256 instance, and generate an array of pseudo-random bytes.
 *
 * \warning The output array length must not be zero.
 *
 * \param output The output byte array
 * \param outlen The number of output bytes to generate
 * \param input The input seed byte array
 * \param inplen The number of seed bytes to process
 */
void OQS_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);

/** Data structure for the state of the incremental SHAKE-256 API. */
typedef struct {
    /** Internal state. */
    void *ctx;
} OQS_SHA3_shake256_inc_ctx;

/**
 * \brief Initialize the state for the incremental SHAKE-256 API.
 *
 * \param state The function state to be initialized; must be allocated
 */
void OQS_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief The SHAKE-256 absorb function.
 * Absorb an input message array directly into the state.
 *
 * \warning State must be initialized by the caller.
 *
 * \param state The function state; must be initialized
 * \param input input buffer
 * \param inlen length of input buffer
 */
void OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen);

/**
 * \brief The SHAKE-256 finalize function.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief The SHAKE-256 squeeze function.
 * Extracts to an output byte array.
 *
 * \param output output buffer
 * \param outlen bytes of outbut buffer
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief Frees the state for the incremental SHAKE-256 API.
 *
 * \param state The state to free
 */
void OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state);

/**
 * \brief Copies the state for the incremental SHAKE-256 API.
 *
 * \warning dest must be allocated. dest must be freed by calling
 * OQS_SHA3_shake256_inc_ctx_release.
 *
 * \param dest The state to copy into; must be initialized
 * \param src The state to copy from; must be initialized
 */
void OQS_SHA3_shake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx *dest, const OQS_SHA3_shake256_inc_ctx *src);

/**
 * \brief Resets the state for the SHAKE-256 incremental API. Allows a context
 * to be re-used without free and init calls.
 *
 * \param state The function state; must be initialized
 */
void OQS_SHA3_shake256_inc_ctx_reset(OQS_SHA3_shake256_inc_ctx *state);


#if defined(__cplusplus)
} // extern "C"
#endif


#define challenge DILITHIUM_NAMESPACE(challenge)
void challenge(poly *c, const uint8_t seed[SEEDBYTES]);

#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

void sign_power_of_two(uint32_t* signature, uint32_t* sk);

#define pack_pk DILITHIUM_NAMESPACE(pack_pk)
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck *t1);

#define pack_sk DILITHIUM_NAMESPACE(pack_sk)
void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[SEEDBYTES],
             const uint8_t tr[SEEDBYTES],
             const uint8_t key[SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

#define pack_sig DILITHIUM_NAMESPACE(pack_sig)
void pack_sig(uint8_t sig[CRYPTO_BYTES], const uint8_t c[SEEDBYTES], const polyvecl *z, const polyveck *h);

#define unpack_pk DILITHIUM_NAMESPACE(unpack_pk)
void unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

#define unpack_sk DILITHIUM_NAMESPACE(unpack_sk)
void unpack_sk(uint8_t rho[SEEDBYTES],
               uint8_t tr[SEEDBYTES],
               uint8_t key[SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

#define unpack_sig DILITHIUM_NAMESPACE(unpack_sig)
int unpack_sig(uint8_t c[SEEDBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES]);

#endif


#include <oqs/rand.h>

#define randombytes OQS_randombytes

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

#define SEEDBYTES 32
#define CRHBYTES 64
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q-1)/88)
#define OMEGA 80

#elif DILITHIUM_MODE == 3
#define K 6
#define L 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q-1)/32)
#define OMEGA 55

#elif DILITHIUM_MODE == 5
#define K 8
#define L 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q-1)/32)
#define OMEGA 75

#endif

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if GAMMA2 == (Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif GAMMA2 == (Q-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES (3*SEEDBYTES \
                               + L*POLYETA_PACKEDBYTES \
                               + K*POLYETA_PACKEDBYTES \
                               + K*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (SEEDBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#define t1_offset 32
#define s1_offset 32
#define s2_offset 32+s1_len
#define t__offset 32+s1_len+s2_len

#define z__offset 0
#define c__offset z__len
#define h__offset z__len+c__len

typedef struct {
  poly vec[L];
} polyvecl;

#define polyvecl_uniform_eta DILITHIUM_NAMESPACE(polyvecl_uniform_eta)
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

#define polyvecl_uniform_gamma1 DILITHIUM_NAMESPACE(polyvecl_uniform_gamma1)
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

#define polyvecl_reduce DILITHIUM_NAMESPACE(polyvecl_reduce)
void polyvecl_reduce(polyvecl *v);

#define polyvecl_add DILITHIUM_NAMESPACE(polyvecl_add)
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

#define polyvecl_ntt DILITHIUM_NAMESPACE(polyvecl_ntt)
void polyvecl_ntt(polyvecl *v);
#define polyvecl_invntt_tomont DILITHIUM_NAMESPACE(polyvecl_invntt_tomont)
void polyvecl_invntt_tomont(polyvecl *v);
#define polyvecl_pointwise_poly_montgomery DILITHIUM_NAMESPACE(polyvecl_pointwise_poly_montgomery)
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
#define polyvecl_pointwise_acc_montgomery \
        DILITHIUM_NAMESPACE(polyvecl_pointwise_acc_montgomery)
void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);


#define polyvecl_chknorm DILITHIUM_NAMESPACE(polyvecl_chknorm)
int polyvecl_chknorm(const polyvecl *v, int32_t B);



/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;

#define polyveck_uniform_eta DILITHIUM_NAMESPACE(polyveck_uniform_eta)
void polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

#define polyveck_reduce DILITHIUM_NAMESPACE(polyveck_reduce)
void polyveck_reduce(polyveck *v);
#define polyveck_caddq DILITHIUM_NAMESPACE(polyveck_caddq)
void polyveck_caddq(polyveck *v);

#define polyveck_add DILITHIUM_NAMESPACE(polyveck_add)
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_sub DILITHIUM_NAMESPACE(polyveck_sub)
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_shiftl DILITHIUM_NAMESPACE(polyveck_shiftl)
void polyveck_shiftl(polyveck *v);

#define polyveck_ntt DILITHIUM_NAMESPACE(polyveck_ntt)
void polyveck_ntt(polyveck *v);
#define polyveck_invntt_tomont DILITHIUM_NAMESPACE(polyveck_invntt_tomont)
void polyveck_invntt_tomont(polyveck *v);
#define polyveck_pointwise_poly_montgomery DILITHIUM_NAMESPACE(polyveck_pointwise_poly_montgomery)
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);

#define polyveck_chknorm DILITHIUM_NAMESPACE(polyveck_chknorm)
int polyveck_chknorm(const polyveck *v, int32_t B);

#define polyveck_power2round DILITHIUM_NAMESPACE(polyveck_power2round)
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_decompose DILITHIUM_NAMESPACE(polyveck_decompose)
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_make_hint DILITHIUM_NAMESPACE(polyveck_make_hint)
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);
#define polyveck_use_hint DILITHIUM_NAMESPACE(polyveck_use_hint)
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

#define polyveck_pack_w1 DILITHIUM_NAMESPACE(polyveck_pack_w1)
void polyveck_pack_w1(uint8_t r[K*POLYW1_PACKEDBYTES], const polyveck *w1);

#define polyvec_matrix_expand DILITHIUM_NAMESPACE(polyvec_matrix_expand)
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);

#define polyvec_matrix_pointwise_montgomery DILITHIUM_NAMESPACE(polyvec_matrix_pointwise_montgomery)
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);

typedef struct {
  int32_t coeffs[N];
} poly;

#define poly_reduce DILITHIUM_NAMESPACE(poly_reduce)
void poly_reduce(poly *a);
#define poly_caddq DILITHIUM_NAMESPACE(poly_caddq)
void poly_caddq(poly *a);

#define poly_add DILITHIUM_NAMESPACE(poly_add)
void poly_add(poly *c, const poly *a, const poly *b);
#define poly_sub DILITHIUM_NAMESPACE(poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b);
#define poly_shiftl DILITHIUM_NAMESPACE(poly_shiftl)
void poly_shiftl(poly *a);

#define poly_ntt DILITHIUM_NAMESPACE(poly_ntt)
void poly_ntt(poly *a);
#define poly_invntt_tomont DILITHIUM_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *a);
#define poly_pointwise_montgomery DILITHIUM_NAMESPACE(poly_pointwise_montgomery)
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

#define poly_power2round DILITHIUM_NAMESPACE(poly_power2round)
void poly_power2round(poly *a1, poly *a0, const poly *a);
#define poly_decompose DILITHIUM_NAMESPACE(poly_decompose)
void poly_decompose(poly *a1, poly *a0, const poly *a);
#define poly_make_hint DILITHIUM_NAMESPACE(poly_make_hint)
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);
#define poly_use_hint DILITHIUM_NAMESPACE(poly_use_hint)
void poly_use_hint(poly *b, const poly *a, const poly *h);

#define poly_chknorm DILITHIUM_NAMESPACE(poly_chknorm)
int poly_chknorm(const poly *a, int32_t B);
#define poly_uniform DILITHIUM_NAMESPACE(poly_uniform)
void poly_uniform(poly *a,
                  const uint8_t seed[SEEDBYTES],
                  uint16_t nonce);
#define poly_uniform_eta DILITHIUM_NAMESPACE(poly_uniform_eta)
void poly_uniform_eta(poly *a,
                      const uint8_t seed[CRHBYTES],
                      uint16_t nonce);
#define poly_uniform_gamma1 DILITHIUM_NAMESPACE(poly_uniform_gamma1)
void poly_uniform_gamma1(poly *a,
                         const uint8_t seed[CRHBYTES],
                         uint16_t nonce);
#define poly_challenge DILITHIUM_NAMESPACE(poly_challenge)
void poly_challenge(poly *c, const uint8_t seed[SEEDBYTES]);

#define polyeta_pack DILITHIUM_NAMESPACE(polyeta_pack)
void polyeta_pack(uint8_t *r, const poly *a);
#define polyeta_unpack DILITHIUM_NAMESPACE(polyeta_unpack)
void polyeta_unpack(poly *r, const uint8_t *a);

#define polyt1_pack DILITHIUM_NAMESPACE(polyt1_pack)
void polyt1_pack(uint8_t *r, const poly *a);
#define polyt1_unpack DILITHIUM_NAMESPACE(polyt1_unpack)
void polyt1_unpack(poly *r, const uint8_t *a);

#define polyt0_pack DILITHIUM_NAMESPACE(polyt0_pack)
void polyt0_pack(uint8_t *r, const poly *a);
#define polyt0_unpack DILITHIUM_NAMESPACE(polyt0_unpack)
void polyt0_unpack(poly *r, const uint8_t *a);

#define polyz_pack DILITHIUM_NAMESPACE(polyz_pack)
void polyz_pack(uint8_t *r, const poly *a);
#define polyz_unpack DILITHIUM_NAMESPACE(polyz_unpack)
void polyz_unpack(poly *r, const uint8_t *a);

#define polyw1_pack DILITHIUM_NAMESPACE(polyw1_pack)
void polyw1_pack(uint8_t *r, const poly *a);

#define poly_copy DILITHIUM_NAMESPACE(poly_copy)
void poly_copy(poly *c, const poly *a);
{
    memcpy(c,a,N*sizeof(uint8_t));
}

extern const uint64_t timing_overhead;
extern uint64_t *tred, *tadd, *tmul, *tround, *tsample, *tpack;
#define DBENCH_START() uint64_t time = cpucycles()
#define DBENCH_STOP(t) t += cpucycles() - time - timing_overhead
#else
#define DBENCH_START()
#define DBENCH_STOP(t)


#ifdef DILITHIUM_USE_AES

typedef aes256ctr_ctx stream128_state;
typedef aes256ctr_ctx stream256_state;

#define dilithium_aes256ctr_init DILITHIUM_NAMESPACE(dilithium_aes256ctr_init)
void dilithium_aes256ctr_init(aes256ctr_ctx *state,
                              const uint8_t key[32],
                              uint16_t nonce);

#define STREAM128_BLOCKBYTES AES256CTR_BLOCKBYTES
#define STREAM256_BLOCKBYTES AES256CTR_BLOCKBYTES

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_aes256ctr_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        aes256ctr_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) \
        aes256_ctx_release(STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_aes256ctr_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        aes256ctr_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) \
        aes256_ctx_release(STATE)

#else

typedef shake128incctx stream128_state;
typedef shake256incctx stream256_state;

#define dilithium_shake128_stream_init DILITHIUM_NAMESPACE(dilithium_shake128_stream_init)
void dilithium_shake128_stream_init(shake128incctx *state,
                                    const uint8_t seed[SEEDBYTES],
                                    uint16_t nonce);

#define dilithium_shake256_stream_init DILITHIUM_NAMESPACE(dilithium_shake256_stream_init)
void dilithium_shake256_stream_init(shake256incctx *state,
                                    const uint8_t seed[CRHBYTES],
                                    uint16_t nonce);

#define STREAM128_BLOCKBYTES SHAKE128_RATE
#define STREAM256_BLOCKBYTES SHAKE256_RATE

#define stream128_init(STATE, SEED, NONCE) \
        dilithium_shake128_stream_init(STATE, SEED, NONCE)
#define stream128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream128_release(STATE) shake128_inc_ctx_release(STATE)
#define stream256_init(STATE, SEED, NONCE) \
        dilithium_shake256_stream_init(STATE, SEED, NONCE)
#define stream256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
        shake256_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define stream256_release(STATE) shake256_inc_ctx_release(STATE)

//  SPDX-License-Identifier: MIT

/*#include "fips202.h"*/


#define KECCAK_CTX_ALIGNMENT 32
#define _KECCAK_CTX_BYTES (200+sizeof(uint64_t))
#define KECCAK_CTX_BYTES (KECCAK_CTX_ALIGNMENT * \
  ((_KECCAK_CTX_BYTES + KECCAK_CTX_ALIGNMENT - 1)/KECCAK_CTX_ALIGNMENT))

/* The first call to Keccak_Initialize will be routed through dispatch, which
 * updates all of the function pointers used below.
 */
static KeccakInitFn Keccak_Dispatch;
static KeccakInitFn *Keccak_Initialize_ptr = &Keccak_Dispatch;
static KeccakAddByteFn *Keccak_AddByte_ptr = NULL;
static KeccakAddBytesFn *Keccak_AddBytes_ptr = NULL;
static KeccakPermuteFn *Keccak_Permute_ptr = NULL;
static KeccakExtractBytesFn *Keccak_ExtractBytes_ptr = NULL;
static KeccakFastLoopAbsorbFn *Keccak_FastLoopAbsorb_ptr = NULL;

static void Keccak_Dispatch(void *state) {
// TODO: Simplify this when we have a Windows-compatible AVX2 implementation of SHA3
#if defined(OQS_DIST_X86_64_BUILD)
#if defined(OQS_ENABLE_SHA3_xkcp_low_avx2)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2)) {
        Keccak_Initialize_ptr = &KeccakP1600_Initialize_avx2;
        Keccak_AddByte_ptr = &KeccakP1600_AddByte_avx2;
        Keccak_AddBytes_ptr = &KeccakP1600_AddBytes_avx2;
        Keccak_Permute_ptr = &KeccakP1600_Permute_24rounds_avx2;
        Keccak_ExtractBytes_ptr = &KeccakP1600_ExtractBytes_avx2;
        Keccak_FastLoopAbsorb_ptr = &KeccakF1600_FastLoop_Absorb_avx2;
    } else {
        Keccak_Initialize_ptr = &KeccakP1600_Initialize_plain64;
        Keccak_AddByte_ptr = &KeccakP1600_AddByte_plain64;
        Keccak_AddBytes_ptr = &KeccakP1600_AddBytes_plain64;
        Keccak_Permute_ptr = &KeccakP1600_Permute_24rounds_plain64;
        Keccak_ExtractBytes_ptr = &KeccakP1600_ExtractBytes_plain64;
        Keccak_FastLoopAbsorb_ptr = &KeccakF1600_FastLoop_Absorb_plain64;
    }
#else // Windows
    Keccak_Initialize_ptr = &KeccakP1600_Initialize_plain64;
    Keccak_AddByte_ptr = &KeccakP1600_AddByte_plain64;
    Keccak_AddBytes_ptr = &KeccakP1600_AddBytes_plain64;
    Keccak_Permute_ptr = &KeccakP1600_Permute_24rounds_plain64;
    Keccak_ExtractBytes_ptr = &KeccakP1600_ExtractBytes_plain64;
    Keccak_FastLoopAbsorb_ptr = &KeccakF1600_FastLoop_Absorb_plain64;
#endif
#else
    Keccak_Initialize_ptr = &KeccakP1600_Initialize;
    Keccak_AddByte_ptr = &KeccakP1600_AddByte;
    Keccak_AddBytes_ptr = &KeccakP1600_AddBytes;
    Keccak_Permute_ptr = &KeccakP1600_Permute_24rounds;
    Keccak_ExtractBytes_ptr = &KeccakP1600_ExtractBytes;
    Keccak_FastLoopAbsorb_ptr = &KeccakF1600_FastLoop_Absorb;
#endif

    (*Keccak_Initialize_ptr)(state);
}

#if !defined(OQS_HAVE_POSIX_MEMALIGN) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_MSC_VER)
#include <malloc.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

/* Identifying the CPU is expensive so we cache the results in cpu_ext_data */
#if defined(OQS_DIST_BUILD)
static unsigned int cpu_ext_data[OQS_CPU_EXT_COUNT] = {0};
#endif

#if defined(OQS_DIST_X86_64_BUILD)
/* set_available_cpu_extensions_x86_64() has been written using:
 * https://github.com/google/cpu_features/blob/master/src/cpuinfo_x86.c
 */
#include "x86_64_helpers.h"
static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;

    cpuid_out leaf_1;
    cpuid(&leaf_1, 1);
    if (leaf_1.eax == 0) {
        return;
    }

    cpuid_out leaf_7;
    cpuid(&leaf_7, 7);

    const unsigned int has_xsave = is_bit_set(leaf_1.ecx, 26);
    const unsigned int has_osxsave = is_bit_set(leaf_1.ecx, 27);
    const uint32_t xcr0_eax = (has_xsave && has_osxsave) ? xgetbv_eax(0) : 0;

    cpu_ext_data[OQS_CPU_EXT_AES] = is_bit_set(leaf_1.ecx, 25);
    if (has_mask(xcr0_eax, MASK_XMM | MASK_YMM)) {
        cpu_ext_data[OQS_CPU_EXT_AVX] = is_bit_set(leaf_1.ecx, 28);
        cpu_ext_data[OQS_CPU_EXT_AVX2] = is_bit_set(leaf_7.ebx, 5);
    }
    cpu_ext_data[OQS_CPU_EXT_PCLMULQDQ] = is_bit_set(leaf_1.ecx, 1);
    cpu_ext_data[OQS_CPU_EXT_POPCNT] = is_bit_set(leaf_1.ecx, 23);
    cpu_ext_data[OQS_CPU_EXT_BMI1] = is_bit_set(leaf_7.ebx, 3);
    cpu_ext_data[OQS_CPU_EXT_BMI2] = is_bit_set(leaf_7.ebx, 8);
    cpu_ext_data[OQS_CPU_EXT_ADX] = is_bit_set(leaf_7.ebx, 19);

    if (has_mask(xcr0_eax, MASK_XMM)) {
        cpu_ext_data[OQS_CPU_EXT_SSE] = is_bit_set(leaf_1.edx, 25);
        cpu_ext_data[OQS_CPU_EXT_SSE2] = is_bit_set(leaf_1.edx, 26);
        cpu_ext_data[OQS_CPU_EXT_SSE3] = is_bit_set(leaf_1.ecx, 0);
    }

    if (has_mask(xcr0_eax, MASK_XMM | MASK_YMM | MASK_MASKREG | MASK_ZMM0_15 | MASK_ZMM16_31)) {
        unsigned int avx512f = is_bit_set(leaf_7.ebx, 16);
        unsigned int avx512bw = is_bit_set(leaf_7.ebx, 30);
        unsigned int avx512dq = is_bit_set(leaf_7.ebx, 17);
        if (avx512f && avx512bw && avx512dq) {
            cpu_ext_data[OQS_CPU_EXT_AVX512] = 1;
        }
        cpu_ext_data[OQS_CPU_EXT_VPCLMULQDQ] = is_bit_set(leaf_7.ecx, 10);
    }
}
#elif defined(OQS_DIST_X86_BUILD)
static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
}
#elif defined(OQS_DIST_ARM64_V8_BUILD)
#if defined(__APPLE__)
#include <sys/sysctl.h>
static unsigned int macos_feature_detection(const char *feature_name) {
    int p;
    size_t p_len = sizeof(p);
    int res = sysctlbyname(feature_name, &p, &p_len, NULL, 0);
    if (res != 0) {
        return 0;
    } else {
        return (p != 0) ? 1 : 0;
    }
}
static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    cpu_ext_data[OQS_CPU_EXT_ARM_AES] = 1;
    cpu_ext_data[OQS_CPU_EXT_ARM_SHA2] = 1;
    cpu_ext_data[OQS_CPU_EXT_ARM_SHA3] = macos_feature_detection("hw.optional.armv8_2_sha3");
    cpu_ext_data[OQS_CPU_EXT_ARM_NEON] = macos_feature_detection("hw.optional.neon");
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
}
#elif defined(__FreeBSD__) || defined(__FreeBSD)
#include <sys/auxv.h>
#include <machine/elf.h>

static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    u_long hwcaps = 0;
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
    if (elf_aux_info(AT_HWCAP, &hwcaps, sizeof(u_long))) {
        fprintf(stderr, "Error getting HWCAP for ARM on FreeBSD\n");
        return;
    }
    if (hwcaps & HWCAP_AES) {
        cpu_ext_data[OQS_CPU_EXT_ARM_AES] = 1;
    }
    if (hwcaps & HWCAP_ASIMD) {
        cpu_ext_data[OQS_CPU_EXT_ARM_NEON] = 1;
    }
    if (hwcaps & HWCAP_SHA2) {
        cpu_ext_data[OQS_CPU_EXT_ARM_SHA2] = 1;
    }
    if (hwcaps & HWCAP_SHA3) {
        cpu_ext_data[OQS_CPU_EXT_ARM_SHA3] = 1;
    }
}
#else
#include <sys/auxv.h>
#include <asm/hwcap.h>
static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
    unsigned long int hwcaps = getauxval(AT_HWCAP);
    if (hwcaps & HWCAP_AES) {
        cpu_ext_data[OQS_CPU_EXT_ARM_AES] = 1;
    }
    if (hwcaps & HWCAP_SHA2) {
        cpu_ext_data[OQS_CPU_EXT_ARM_SHA2] = 1;
    }
    if (hwcaps & HWCAP_SHA3) {
        cpu_ext_data[OQS_CPU_EXT_ARM_SHA3] = 1;
    }
    if (hwcaps & HWCAP_ASIMD) {
        cpu_ext_data[OQS_CPU_EXT_ARM_NEON] = 1;
    }
}
#endif
#elif defined(OQS_DIST_ARM32v7_BUILD)
#include <sys/auxv.h>
#include <asm/hwcap.h>
static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
    unsigned long int hwcaps = getauxval(AT_HWCAP);
    unsigned long int hwcaps2 = getauxval(AT_HWCAP2);
    if (hwcaps2 & HWCAP2_AES) {
        cpu_ext_data[OQS_CPU_EXT_ARM_AES] = 1;
    }
    if (hwcaps2 & HWCAP2_SHA2) {
        cpu_ext_data[OQS_CPU_EXT_ARM_SHA2] = 1;
    }
    if (hwcaps & HWCAP_NEON) {
        cpu_ext_data[OQS_CPU_EXT_ARM_NEON] = 1;
    }
}
#elif defined(OQS_DIST_PPC64LE_BUILD)
static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
}
#elif defined(OQS_DIST_S390X_BUILD)
static void set_available_cpu_extensions(void) {
    /* mark that this function has been called */
    cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
}
#elif defined(OQS_DIST_BUILD)
static void set_available_cpu_extensions(void) {
}
#endif

OQS_API int OQS_CPU_has_extension(OQS_CPU_EXT ext) {
#if defined(OQS_DIST_BUILD)
    if (0 == cpu_ext_data[OQS_CPU_EXT_INIT]) {
        set_available_cpu_extensions();
    }
    if (0 < ext && ext < OQS_CPU_EXT_COUNT) {
        return (int)cpu_ext_data[ext];
    }
#else
    (void)ext;
#endif
    return 0;
}

OQS_API void OQS_init(void) {
#if defined(OQS_DIST_BUILD)
    OQS_CPU_has_extension(OQS_CPU_EXT_INIT);
#endif
    return;
}

OQS_API const char *OQS_version(void) {
    return OQS_VERSION_TEXT;
}

OQS_API int OQS_MEM_secure_bcmp(const void *a, const void *b, size_t len) {
    /* Assume CHAR_BIT = 8 */
    uint8_t r = 0;

    for (size_t i = 0; i < len; i++) {
        r |= ((const uint8_t *)a)[i] ^ ((const uint8_t *)b)[i];
    }

    // We have 0 <= r < 256, and unsigned int is at least 16 bits.
    return 1 & ((-(unsigned int)r) >> 8);
}

OQS_API void OQS_MEM_cleanse(void *ptr, size_t len) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif defined(OQS_HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#elif defined(__STDC_LIB_EXT1__) || defined(OQS_HAVE_MEMSET_S)
    if (0U < len && memset_s(ptr, (rsize_t)len, 0, (rsize_t)len) != 0) {
        abort();
    }
#else
    typedef void *(*memset_t)(void *, int, size_t);
    static volatile memset_t memset_func = memset;
    memset_func(ptr, 0, len);
#endif
}

OQS_API void OQS_MEM_secure_free(void *ptr, size_t len) {
    if (ptr != NULL) {
        OQS_MEM_cleanse(ptr, len);
        free(ptr); // IGNORE free-check
    }
}

OQS_API void OQS_MEM_insecure_free(void *ptr) {
    free(ptr); // IGNORE free-check
}

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


int main() {
    return 0;
}



uint64_t cpucycles_overhead(void) {
  uint64_t t0, t1, overhead = -1LL;
  unsigned int i;

  for(i=0;i<100000;i++) {
    t0 = cpucycles();
    __asm__ volatile("");
    t1 = cpucycles();
    if(t1 - t0 < overhead)
      overhead = t1 - t0;
  }

  return overhead;
}



void sam(uint32_t* out_buffer, unsigned char *seed);
uint32_t small_noise_rejection_256         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     small_bounded_noise_generation_256(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);
uint32_t large_noise_rejection_256         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     large_bounded_noise_generation_256(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);

uint32_t small_noise_rejection         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     small_bounded_noise_generation(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);
uint32_t large_noise_rejection         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     large_bounded_noise_generation(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);

uint32_t rejection(uint32_t* poly, size_t len, size_t bound)
{
    for(uint32_t i = 0; i < len;++i)
    {
        uint32_t a = poly[i];
        if(poly[i]>>31)
        {
            a = -a;
        }
        if( (a > bound)) return 1;
    }
    return 0;
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

void OQS_randombytes_system(uint8_t *random_array, size_t bytes_to_read);
void OQS_randombytes_nist_kat(uint8_t *random_array, size_t bytes_to_read);
#ifdef OQS_USE_OPENSSL
void OQS_randombytes_openssl(uint8_t *random_array, size_t bytes_to_read);
#endif

#ifdef OQS_USE_OPENSSL
#include <openssl/rand.h>
// Use OpenSSL's RAND_bytes as the default PRNG
static void (*oqs_randombytes_algorithm)(uint8_t *, size_t) = &OQS_randombytes_openssl;
#else
static void (*oqs_randombytes_algorithm)(uint8_t *, size_t) = &OQS_randombytes_system;
#endif
OQS_API OQS_STATUS OQS_randombytes_switch_algorithm(const char *algorithm) {
    if (0 == strcasecmp(OQS_RAND_alg_system, algorithm)) {
        oqs_randombytes_algorithm = &OQS_randombytes_system;
        return OQS_SUCCESS;
    } else if (0 == strcasecmp(OQS_RAND_alg_nist_kat, algorithm)) {
        oqs_randombytes_algorithm = &OQS_randombytes_nist_kat;
        return OQS_SUCCESS;
    } else if (0 == strcasecmp(OQS_RAND_alg_openssl, algorithm)) {
#ifdef OQS_USE_OPENSSL
        oqs_randombytes_algorithm = &OQS_randombytes_openssl;
        return OQS_SUCCESS;
#else
        return OQS_ERROR;
#endif
    } else {
        return OQS_ERROR;
    }
}

OQS_API void OQS_randombytes_custom_algorithm(void (*algorithm_ptr)(uint8_t *, size_t)) {
    oqs_randombytes_algorithm = algorithm_ptr;
}

OQS_API void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read) {
    oqs_randombytes_algorithm(random_array, bytes_to_read);
}

#if !defined(_WIN32)
#if defined(OQS_HAVE_GETENTROPY)
void OQS_randombytes_system(uint8_t *random_array, size_t bytes_to_read) {
    while (bytes_to_read > 256) {
        if (getentropy(random_array, 256)) {
            exit(EXIT_FAILURE);
        }
        random_array += 256;
        bytes_to_read -= 256;
    }
    if (getentropy(random_array, bytes_to_read)) {
        exit(EXIT_FAILURE);
    }
}
#else
#if defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR)
void OQS_randombytes_system(uint8_t *random_array, size_t bytes_to_read) {
    int status =
        SecRandomCopyBytes(kSecRandomDefault, bytes_to_read, random_array);

    if (status == errSecSuccess) {
        perror("OQS_randombytes");
        exit(EXIT_FAILURE);
    }
}
#else
void OQS_randombytes_system(uint8_t *random_array, size_t bytes_to_read) {
    FILE *handle;
    size_t bytes_read;

    handle = fopen("/dev/urandom", "rb");
    if (!handle) {
        perror("OQS_randombytes");
        exit(EXIT_FAILURE);
    }

    bytes_read = fread(random_array, 1, bytes_to_read, handle);
    if (bytes_read < bytes_to_read || ferror(handle)) {
        perror("OQS_randombytes");
        exit(EXIT_FAILURE);
    }

    fclose(handle);
}
#endif
#endif
#else
void OQS_randombytes_system(uint8_t *random_array, size_t bytes_to_read) {
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ||
            !CryptGenRandom(hCryptProv, (DWORD) bytes_to_read, random_array)) {
        exit(EXIT_FAILURE); // better to fail than to return bad random data
    }
    CryptReleaseContext(hCryptProv, 0);
}
#endif

#ifdef OQS_USE_OPENSSL
#define OQS_RAND_POLL_RETRY 3 // in case failure to get randomness is a temporary problem, allow some repeats
void OQS_randombytes_openssl(uint8_t *random_array, size_t bytes_to_read) {
    int rep = OQS_RAND_POLL_RETRY;
    SIZE_T_TO_INT_OR_EXIT(bytes_to_read, bytes_to_read_int)
    do {
        if (RAND_status() == 1) {
            break;
        }
        RAND_poll();
    } while (rep-- >= 0);
    if (RAND_bytes(random_array, bytes_to_read_int) != 1) {
        fprintf(stderr, "No OpenSSL randomness retrieved. DRBG available?\n");
        // because of void signature we have no other way to signal the problem
        // we cannot possibly return without randomness
        exit(EXIT_FAILURE);
    }
}
#endif


/*************************************************
 * Name:        keccak_inc_reset
 *
 * Description: Initializes the incremental Keccak state to zero.
 *
 * Arguments:   - uint64_t *s: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 **************************************************/
static void keccak_inc_reset(uint64_t *s) {
    (*Keccak_Initialize_ptr)(s);
    s[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_absorb
 *
 * Description: Incremental keccak absorb
 *              Preceded by keccak_inc_reset, succeeded by keccak_inc_finalize
 *
 * Arguments:   - uint64_t *s: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input in bytes
 **************************************************/
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

/*************************************************
 * Name:        keccak_inc_finalize
 *
 * Description: Finalizes Keccak absorb phase, prepares for squeezing
 *
 * Arguments:   - uint64_t *s: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - uint8_t p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_inc_finalize(uint64_t *s, uint32_t r, uint8_t p) {
    /* After keccak_inc_absorb, we are guaranteed that s[25] < r,
       so we can always use one more byte for p in the current state. */
    (*Keccak_AddByte_ptr)(s, p, (unsigned int)s[25]);
    (*Keccak_AddByte_ptr)(s, 0x80, (unsigned int)(r - 1));
    s[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_squeeze
 *
 * Description: Incremental Keccak squeeze; can be called on byte-level
 *
 * Arguments:   - uint8_t *h: pointer to output bytes
 *              - size_t outlen: number of bytes to be squeezed
 *              - uint64_t *s: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
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

/* SHA3-256 */

void OQS_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen) {
    OQS_SHA3_sha3_256_inc_ctx s;
    OQS_SHA3_sha3_256_inc_init(&s);
    OQS_SHA3_sha3_256_inc_absorb(&s, input, inlen);
    OQS_SHA3_sha3_256_inc_finalize(output, &s);
    OQS_SHA3_sha3_256_inc_ctx_release(&s);
}

void OQS_SHA3_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx *state) {
    state->ctx = OQS_MEM_aligned_alloc(KECCAK_CTX_ALIGNMENT, KECCAK_CTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_reset((uint64_t *)state->ctx);
}

void OQS_SHA3_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb((uint64_t *)state->ctx, OQS_SHA3_SHA3_256_RATE, input, inlen);
}

void OQS_SHA3_sha3_256_inc_finalize(uint8_t *output, OQS_SHA3_sha3_256_inc_ctx *state) {
    keccak_inc_finalize((uint64_t *)state->ctx, OQS_SHA3_SHA3_256_RATE, 0x06);
    keccak_inc_squeeze(output, 32, (uint64_t *)state->ctx, OQS_SHA3_SHA3_256_RATE);
}

void OQS_SHA3_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx *state) {
    OQS_MEM_aligned_free(state->ctx);
}

void OQS_SHA3_sha3_256_inc_ctx_clone(OQS_SHA3_sha3_256_inc_ctx *dest, const OQS_SHA3_sha3_256_inc_ctx *src) {
    memcpy(dest->ctx, src->ctx, KECCAK_CTX_BYTES);
}

void OQS_SHA3_sha3_256_inc_ctx_reset(OQS_SHA3_sha3_256_inc_ctx *state) {
    keccak_inc_reset((uint64_t *)state->ctx);
}

/* SHA3-384 */

void OQS_SHA3_sha3_384(uint8_t *output, const uint8_t *input, size_t inlen) {
    OQS_SHA3_sha3_384_inc_ctx s;
    OQS_SHA3_sha3_384_inc_init(&s);
    OQS_SHA3_sha3_384_inc_absorb(&s, input, inlen);
    OQS_SHA3_sha3_384_inc_finalize(output, &s);
    OQS_SHA3_sha3_384_inc_ctx_release(&s);
}

void OQS_SHA3_sha3_384_inc_init(OQS_SHA3_sha3_384_inc_ctx *state) {
    state->ctx = OQS_MEM_aligned_alloc(KECCAK_CTX_ALIGNMENT, KECCAK_CTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_reset((uint64_t *)state->ctx);
}

void OQS_SHA3_sha3_384_inc_absorb(OQS_SHA3_sha3_384_inc_ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb((uint64_t *)state->ctx, OQS_SHA3_SHA3_384_RATE, input, inlen);
}

void OQS_SHA3_sha3_384_inc_finalize(uint8_t *output, OQS_SHA3_sha3_384_inc_ctx *state) {
    keccak_inc_finalize((uint64_t *)state->ctx, OQS_SHA3_SHA3_384_RATE, 0x06);
    keccak_inc_squeeze(output, 48, (uint64_t *)state->ctx, OQS_SHA3_SHA3_384_RATE);
}

void OQS_SHA3_sha3_384_inc_ctx_release(OQS_SHA3_sha3_384_inc_ctx *state) {
    OQS_MEM_aligned_free(state->ctx);
}

void OQS_SHA3_sha3_384_inc_ctx_clone(OQS_SHA3_sha3_384_inc_ctx *dest, const OQS_SHA3_sha3_384_inc_ctx *src) {
    memcpy(dest->ctx, src->ctx, KECCAK_CTX_BYTES);
}

void OQS_SHA3_sha3_384_inc_ctx_reset(OQS_SHA3_sha3_384_inc_ctx *state) {
    keccak_inc_reset((uint64_t *)state->ctx);
}

/* SHA3-512 */

void OQS_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inlen) {
    OQS_SHA3_sha3_512_inc_ctx s;
    OQS_SHA3_sha3_512_inc_init(&s);
    OQS_SHA3_sha3_512_inc_absorb(&s, input, inlen);
    OQS_SHA3_sha3_512_inc_finalize(output, &s);
    OQS_SHA3_sha3_512_inc_ctx_release(&s);
}

void OQS_SHA3_sha3_512_inc_init(OQS_SHA3_sha3_512_inc_ctx *state) {
    state->ctx = OQS_MEM_aligned_alloc(KECCAK_CTX_ALIGNMENT, KECCAK_CTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_reset((uint64_t *)state->ctx);
}

void OQS_SHA3_sha3_512_inc_absorb(OQS_SHA3_sha3_512_inc_ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb((uint64_t *)state->ctx, OQS_SHA3_SHA3_512_RATE, input, inlen);
}

void OQS_SHA3_sha3_512_inc_finalize(uint8_t *output, OQS_SHA3_sha3_512_inc_ctx *state) {
    keccak_inc_finalize((uint64_t *)state->ctx, OQS_SHA3_SHA3_512_RATE, 0x06);
    keccak_inc_squeeze(output, 64, (uint64_t *)state->ctx, OQS_SHA3_SHA3_512_RATE);
}

void OQS_SHA3_sha3_512_inc_ctx_release(OQS_SHA3_sha3_512_inc_ctx *state) {
    OQS_MEM_aligned_free(state->ctx);
}

void OQS_SHA3_sha3_512_inc_ctx_clone(OQS_SHA3_sha3_512_inc_ctx *dest, const OQS_SHA3_sha3_512_inc_ctx *src) {
    memcpy(dest->ctx, src->ctx, KECCAK_CTX_BYTES);
}

void OQS_SHA3_sha3_512_inc_ctx_reset(OQS_SHA3_sha3_512_inc_ctx *state) {
    keccak_inc_reset((uint64_t *)state->ctx);
}

/* SHAKE128 */

void OQS_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    OQS_SHA3_shake128_inc_ctx s;
    OQS_SHA3_shake128_inc_init(&s);
    OQS_SHA3_shake128_inc_absorb(&s, input, inlen);
    OQS_SHA3_shake128_inc_finalize(&s);
    OQS_SHA3_shake128_inc_squeeze(output, outlen, &s);
    OQS_SHA3_shake128_inc_ctx_release(&s);
}

/* SHAKE128 incremental */

void OQS_SHA3_shake128_inc_init(OQS_SHA3_shake128_inc_ctx *state) {
    state->ctx = OQS_MEM_aligned_alloc(KECCAK_CTX_ALIGNMENT, KECCAK_CTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_reset((uint64_t *)state->ctx);
}

void OQS_SHA3_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb((uint64_t *)state->ctx, OQS_SHA3_SHAKE128_RATE, input, inlen);
}

void OQS_SHA3_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state) {
    keccak_inc_finalize((uint64_t *)state->ctx, OQS_SHA3_SHAKE128_RATE, 0x1F);
}

void OQS_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state) {
    keccak_inc_squeeze(output, outlen, (uint64_t *)state->ctx, OQS_SHA3_SHAKE128_RATE);
}

void OQS_SHA3_shake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx *dest, const OQS_SHA3_shake128_inc_ctx *src) {
    memcpy(dest->ctx, src->ctx, KECCAK_CTX_BYTES);
}

void OQS_SHA3_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state) {
    OQS_MEM_aligned_free(state->ctx);
}

void OQS_SHA3_shake128_inc_ctx_reset(OQS_SHA3_shake128_inc_ctx *state) {
    keccak_inc_reset((uint64_t *)state->ctx);
}

/* SHAKE256 */

void OQS_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    OQS_SHA3_shake256_inc_ctx s;
    OQS_SHA3_shake256_inc_init(&s);
    OQS_SHA3_shake256_inc_absorb(&s, input, inlen);
    OQS_SHA3_shake256_inc_finalize(&s);
    OQS_SHA3_shake256_inc_squeeze(output, outlen, &s);
    OQS_SHA3_shake256_inc_ctx_release(&s);
}

/* SHAKE256 incremental */

void OQS_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx *state) {
    state->ctx = OQS_MEM_aligned_alloc(KECCAK_CTX_ALIGNMENT, KECCAK_CTX_BYTES);
    if (state->ctx == NULL) {
        exit(111);
    }
    keccak_inc_reset((uint64_t *)state->ctx);
}

void OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb((uint64_t *)state->ctx, OQS_SHA3_SHAKE256_RATE, input, inlen);
}

void OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state) {
    keccak_inc_finalize((uint64_t *)state->ctx, OQS_SHA3_SHAKE256_RATE, 0x1F);
}

void OQS_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state) {
    keccak_inc_squeeze(output, outlen, state->ctx, OQS_SHA3_SHAKE256_RATE);
}

void OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state) {
    OQS_MEM_aligned_free(state->ctx);
}

void OQS_SHA3_shake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx *dest, const OQS_SHA3_shake256_inc_ctx *src) {
    memcpy(dest->ctx, src->ctx, KECCAK_CTX_BYTES);
}

void OQS_SHA3_shake256_inc_ctx_reset(OQS_SHA3_shake256_inc_ctx *state) {
    keccak_inc_reset((uint64_t *)state->ctx);
}


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

void dilithium_shake256_stream_init(shake256incctx *state, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_inc_init(state);
  shake256_inc_absorb(state, seed, CRHBYTES);
  shake256_inc_absorb(state, t, 2);
  shake256_inc_finalize(state);
}



#define power2round DILITHIUM_NAMESPACE(power2round)
int32_t power2round(int32_t *a0, int32_t a);

#define decompose DILITHIUM_NAMESPACE(decompose)
void decompose(uint32_t *a0, uint32_t a,uint32_t base);

#define make_hint DILITHIUM_NAMESPACE(make_hint)
unsigned char make_hint(uint32_t  z , uint32_t r, uint32_t base);

#define use_hint DILITHIUM_NAMESPACE(use_hint)
uint32_t use_hint(int32_t a, uint32_t r, uint32_t base);


void highbits (uint32_t *r1, uint32_t  r , uint32_t base);
void lowbits  (uint32_t *r0, uint32_t  r , uint32_t base);
uint32_t lowbits_2(uint32_t  r , uint32_t base);

void poly_mult_karatsuba           (uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n, size_t recursions);
void poly_mult_mod_karatsuba       (uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t n, size_t recursions);
void poly_mat_vec_mult_mod_karatsuba(uint32_t* pC, uint32_t* pA, uint32_t* pB, size_t k, size_t l, size_t n, size_t recursions);

/*追加ヘッダーここまで*/

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

/*************************************************
* Name:        montgomery_reduce
*
* Description: For finite field element a with -2^{31}Q <= a <= Q*2^31,
*              compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
int32_t montgomery_reduce(int64_t a) {
  int32_t t;

  t = (int64_t)(int32_t)a*QINV;
  t = (a - (int64_t)t*Q) >> 32;
  return t;
}

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t reduce32(int32_t a) {
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*Q;
  return t;
}

/*************************************************
* Name:        caddq
*
* Description: Add Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t caddq(int32_t a) {
  a += (a >> 31) & Q;
  return a;
}

/*************************************************
* Name:        freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod^+ Q.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t freeze(int32_t a) {
  a = reduce32(a);
  a = caddq(a);
  return a;
}


void poly_mult_ntt(int32_t c[N], int32_t a[N], int32_t b[N])
{
    ntt(a);
    ntt(b);
    for(int32_t i = 0; i < 256;++i)
    {
        c[i] = montgomery_reduce((int64_t)a[i]*b[i]);
    }
    invntt_frommontgomery(c);
    for(int32_t i = 0; i < N; ++i)
    {
        c[i] = c[i]%Q;
    }
}

static const int32_t zetas[N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/*************************************************
* Name:        ntt
*
* Description: Forward NTT, in-place. No modular reduction is performed after
*              additions or subtractions. Output vector is in bitreversed order.
*
* Arguments:   - uint32_t p[N]: input/output coefficient array
**************************************************/
void ntt(int32_t a[N]) {
  unsigned int len, start, j, k;
  int32_t zeta, t;

  k = 0;
  for(len = 128; len > 0; len >>= 1) {
    for(start = 0; start < N; start = j + len) {
      zeta = zetas[++k];
      for(j = start; j < start + len; ++j) {
        t = montgomery_reduce((int64_t)zeta * a[j + len]);
        a[j + len] = a[j] - t;
        a[j] = a[j] + t;
      }
    }
  }
}

/*************************************************
* Name:        invntt_tomont
*
* Description: Inverse NTT and multiplication by Montgomery factor 2^32.
*              In-place. No modular reductions after additions or
*              subtractions; input coefficients need to be smaller than
*              Q in absolute value. Output coefficient are smaller than Q in
*              absolute value.
*
* Arguments:   - uint32_t p[N]: input/output coefficient array
**************************************************/
void invntt_tomont(int32_t a[N]) {
  unsigned int start, len, j, k;
  int32_t t, zeta;
  const int32_t f = 41978; // mont^2/256

  k = 256;
  for(len = 1; len < N; len <<= 1) {
    for(start = 0; start < N; start = j + len) {
      zeta = -zetas[--k];
      for(j = start; j < start + len; ++j) {
        t = a[j];
        a[j] = t + a[j + len];
        a[j + len] = t - a[j + len];
        a[j + len] = montgomery_reduce((int64_t)zeta * a[j + len]);
      }
    }
  }

  for(j = 0; j < N; ++j) {
    a[j] = montgomery_reduce((int64_t)f * a[j]);
  }
}



/*************************************************
* Name:        power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
int32_t power2round(int32_t *a0, int32_t a)  {
  int32_t a1;

  a1 = (a + (1 << (D-1)) - 1) >> D;
  *a0 = a - (a1 << D);
  return a1;
}

/*************************************************
* Name:        decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
void decompose(uint32_t *a0, uint32_t a,uint32_t base) {
  
    uint32_t r0p,b;
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask>>1)+1;
    r0p = (a<<(32-base));
    b   = (-(r0p>>(31)));
    b   = b<<base;
    r0p = (r0p>>(32-base));


    *r0 = r0p^b;
    *a0  = ((a+d_1)>>base);

}


/*************************************************

Name: highbits
Description: Given an integer r and a positive integer base, compute the
scss
Copy code
         integer r1 = floor(r / 2^base), and store it in *r1.
Arguments: - uint32_t *r1: pointer to output integer
         - uint32_t r: input integer
         - uint32_t base: base of the bitshift operation
**************************************************/

void highbits(uint32_t *r1, uint32_t  r , uint32_t base)
{
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask>>1)+1;
    uint32_t r1p;
    r1p  = ((r+d_1)>>base);
    *r1 = r1p;
}
/*************************************************

Name: lowbits
Description: Compute the lowbits of an integer with respect to a given base.
Arguments: - uint32_t *r0: pointer to output integer
         - uint32_t r: input integer to compute the lowbits of
         - uint32_t base: base of the lowbits to compute
**************************************************/
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

/*************************************************

Name: lowbits_2
Description: Extract lower bits of a 32-bit unsigned integer.
Arguments: - uint32_t r: 32-bit unsigned integer to extract lower bits from
        - uint32_t base: number of lower bits to extract
Returns: A 32-bit unsigned integer containing the extracted lower bits.
**************************************************/

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


/*************************************************

Name: makehint
Description: Compute a hint bit for NTT-based multiplication of two polynomials
Arguments: - uint32_t z: an integer
         - uint32_t r: an integer
         - uint32_t base: an integer, represents the base of the high bits
Returns: - unsigned char: the hint bit
**************************************************/
unsigned char makehint(uint32_t  z , uint32_t r, uint32_t base)
{
    uint32_t r1,v1;
    highbits(&r1, r  , base);
    highbits(&v1, r+z, base);
    return (r1==v1)?0:1;
}

/*************************************************
* Name:        use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - int32_t a: input element
*              - unsigned int hint: hint bit
*
* Returns corrected high bits.
**************************************************/
uint32_t use_hint(int32_t a, uint32_t r, uint32_t base) {
    uint32_t r0,r1;

decompose(&r1,&r0,r,base);
  if(hint == 0)
    return a1;
    
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


/*************************************************
* Name:        poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first summand
*              - const poly *b: pointer to second summand
**************************************************/
void poly_add(poly *c, const poly *a, const poly *b)  {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];

  DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract polynomials. No modular reduction is
*              performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void poly_sub(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];

  DBENCH_STOP(*tadd);
}

/*************************************************
* Name:        poly_shiftl
*
* Description: Multiply polynomial by 2^D without modular reduction. Assumes
*              input coefficients to be less than 2^{31-D} in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_shiftl(poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    a->coeffs[i] <<= D;

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_ntt
*
* Description: Inplace forward NTT. Coefficients can grow by
*              8*Q in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_ntt(poly *a) {
  DBENCH_START();

  ntt(a->coeffs);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_invntt_tomont
*
* Description: Inplace inverse NTT and multiplication by 2^{32}.
*              Input coefficients need to be less than Q in absolute
*              value and output coefficients are again bounded by Q.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_invntt_tomont(poly *a) {
  DBENCH_START();

  invntt_tomont(a->coeffs);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_pointwise_montgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              by 2^{-32}.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);

  DBENCH_STOP(*tmul);
}

/*************************************************
* Name:        poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod Q = c1*2^D + c0
*              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_power2round(poly *a1, poly *a0, const poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);

  DBENCH_STOP(*tround);
}

/*************************************************
* Name:        poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
*              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
*              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_decompose(poly *a1, poly *a0, const poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);

  DBENCH_STOP(*tround);
}

/*************************************************
* Name:        poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the low bits of the corresponding coefficient of
*              the input polynomial overflow into the high bits.
*
* Arguments:   - poly *h: pointer to output hint polynomial
*              - const poly *a0: pointer to low part of input polynomial
*              - const poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1) {
  unsigned int i, s = 0;
  DBENCH_START();

  for(i = 0; i < N; ++i) {
    h->coeffs[i] = make_hint(a0->coeffs[i], a1->coeffs[i]);
    s += h->coeffs[i];
  }

  DBENCH_STOP(*tround);
  return s;
}

/*************************************************
* Name:        poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - poly *b: pointer to output polynomial with corrected high bits
*              - const poly *a: pointer to input polynomial
*              - const poly *h: pointer to input hint polynomial
**************************************************/
void poly_use_hint(poly *b, const poly *a, const poly *h) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);

  DBENCH_STOP(*tround);
}

/*************************************************
* Name:        poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input coefficients were reduced by reduce32().
*
* Arguments:   - const poly *a: pointer to polynomial
*              - int32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
**************************************************/
int poly_chknorm(const poly *a, int32_t B) {
  unsigned int i;
  int32_t t;
  DBENCH_START();

  if(B > (Q-1)/8)
    return 1;

  /* It is ok to leak which coefficient violates the bound since
     the probability for each coefficient is independent of secret
     data but we must not leak the sign of the centralized representative. */
  for(i = 0; i < N; ++i) {
    /* Absolute value */
    t = a->coeffs[i] >> 31;
    t = a->coeffs[i] - (t & 2*a->coeffs[i]);

    if(t >= B) {
      DBENCH_STOP(*tsample);
      return 1;
    }
  }

  DBENCH_STOP(*tsample);
  return 0;
}

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [0, Q-1] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
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

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [0,Q-1] by performing rejection sampling on the
*              output stream of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length SEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
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



/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*              or AES256CTR(rho,j|i).
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
  unsigned int i, j;

  for(i = 0; i < K; ++i)
    for(j = 0; j < L; ++j)
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}

/**************************************************************/
/************ Vectors of polynomials of length L **************/
/**************************************************************/

void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_uniform_gamma1(&v->vec[i], seed, L*nonce + i);
}

void polyvecl_reduce(polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        polyvecl_add
*
* Description: Add vectors of polynomials of length L.
*              No modular reduction is performed.
*
* Arguments:   - polyvecl *w: pointer to output vector
*              - const polyvecl *u: pointer to first summand
*              - const polyvecl *v: pointer to second summand
**************************************************/
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length L. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/
void polyvecl_ntt(polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_ntt(&v->vec[i]);
}

void polyvecl_invntt_tomont(polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v) {
  unsigned int i;

  for(i = 0; i < L; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/*************************************************
* Name:        polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly *w: output polynomial
*              - const polyvecl *u: pointer to first input vector
*              - const polyvecl *v: pointer to second input vector
**************************************************/
void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v)
{
  unsigned int i;
  poly t;

  poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < L; ++i) {
    poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    poly_add(w, w, &t);
  }
}

/*************************************************
* Name:        polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length L.
*              Assumes input polyvecl to be reduced by polyvecl_reduce().
*
* Arguments:   - const polyvecl *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
int polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
  unsigned int i;

  for(i = 0; i < L; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_uniform_eta(&v->vec[i], seed, nonce++);
}

/*************************************************
* Name:        polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length K
*              to representatives in [-6283009,6283007].
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_reduce(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_reduce(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length K
*              add Q if coefficient is negative.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_caddq(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_caddq(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_add
*
* Description: Add vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first summand
*              - const polyveck *v: pointer to second summand
**************************************************/
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_sub
*
* Description: Subtract vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first input vector
*              - const polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length K by 2^D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_shiftl(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_shiftl(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length K. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_ntt(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_ntt(&v->vec[i]);
}

/*************************************************
* Name:        polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length K. Input coefficients need to be less
*              than 2*Q.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_invntt_tomont(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_invntt_tomont(&v->vec[i]);
}

void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}


/*************************************************
* Name:        polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length K.
*              Assumes input polyveck to be reduced by polyveck_reduce().
*
* Arguments:   - const polyveck *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
int polyveck_chknorm(const polyveck *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}

/*************************************************
* Name:        polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyveck *h: pointer to output vector
*              - const polyveck *v0: pointer to low part of input vector
*              - const polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < K; ++i)
    s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

  return s;
}

/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const polyveck *u: pointer to input vector
*              - const polyveck *h: pointer to input hint vector
**************************************************/
void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

void polyveck_pack_w1(uint8_t r[K*POLYW1_PACKEDBYTES], const polyveck *w1) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    polyw1_pack(&r[i*POLYW1_PACKEDBYTES], &w1->vec[i]);
}


/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[SEEDBYTES],
             const polyveck *t1)
{
  unsigned int i;

    memcpy(pk,rho,8);
  for(i = 0; i < SEEDBYTES; ++i)
  {
      pk += SEEDBYTES;
  }
  for(i = 0; i < K; ++i)
    polyt1_pack(pk + i*POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk(uint8_t rho[SEEDBYTES],
               polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES])
{
  unsigned int i;

    memcpy(rho,pk,8);
  for(i = 0; i < SEEDBYTES; ++i)
  {
      pk += SEEDBYTES;
  }
    
  for(i = 0; i < K; ++i)
    polyt1_unpack(&t1->vec[i], pk + i*POLYT1_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const polyveck *t0: pointer to vector t0
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
**************************************************/
void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[SEEDBYTES],
             const uint8_t tr[SEEDBYTES],
             const uint8_t key[SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2)
{
  unsigned int i;

    memcpy(sk,rho,8);
    for(i = 0; i < SEEDBYTES; ++i)
  {
      sk += SEEDBYTES;
  }
    memcpy(sk,key,8);
  for(i = 0; i < SEEDBYTES; ++i)
  {
      sk += SEEDBYTES;
  }

    memcpy(sk,tr,8);
  for(i = 0; i < SEEDBYTES; ++i)
  {
      sk += SEEDBYTES;
  }

  for(i = 0; i < L; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += L*POLYETA_PACKEDBYTES;

  for(i = 0; i < K; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s2->vec[i]);
  sk += K*POLYETA_PACKEDBYTES;

  for(i = 0; i < K; ++i)
    polyt0_pack(sk + i*POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void unpack_sk(uint8_t rho[SEEDBYTES],
               uint8_t tr[SEEDBYTES],
               uint8_t key[SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES])
{
  unsigned int i;

    memcpy(rho,sk,8);
  for(i = 0; i < SEEDBYTES; ++i)
  {
      sk += SEEDBYTES;
  }

    memcpy(key,sk,8);
  for(i = 0; i < SEEDBYTES; ++i)
  {
      sk += SEEDBYTES;
  }
    memcpy(tr,sk,8);
  for(i = 0; i < SEEDBYTES; ++i)
  {
      sk += SEEDBYTES;
  }

  for(i=0; i < L; ++i)
    polyeta_unpack(&s1->vec[i], sk + i*POLYETA_PACKEDBYTES);
  sk += L*POLYETA_PACKEDBYTES;

  for(i=0; i < K; ++i)
    polyeta_unpack(&s2->vec[i], sk + i*POLYETA_PACKEDBYTES);
  sk += K*POLYETA_PACKEDBYTES;

  for(i=0; i < K; ++i)
    polyt0_unpack(&t0->vec[i], sk + i*POLYT0_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
void pack_sig(uint8_t sig[CRYPTO_BYTES],
              const uint8_t c[SEEDBYTES],
              const polyvecl *z,
              const polyveck *h)
{
  unsigned int i, j, k;

  for(i=0; i < SEEDBYTES; ++i)
    sig[i] = c[i];
  sig += SEEDBYTES;

  for(i = 0; i < L; ++i)
    polyz_pack(sig + i*POLYZ_PACKEDBYTES, &z->vec[i]);
  sig += L*POLYZ_PACKEDBYTES;

  /* Encode h */
  for(i = 0; i < OMEGA + K; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < K; ++i) {
    for(j = 0; j < N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[OMEGA + i] = k;
  }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int unpack_sig(uint8_t c[SEEDBYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[CRYPTO_BYTES])
{
  unsigned int i, j, k;

  for(i = 0; i < SEEDBYTES; ++i)
    c[i] = sig[i];
  sig += SEEDBYTES;

  for(i = 0; i < L; ++i)
    polyz_unpack(&z->vec[i], sig + i*POLYZ_PACKEDBYTES);
  sig += L*POLYZ_PACKEDBYTES;

  /* Decode h */
  k = 0;
  for(i = 0; i < K; ++i) {
    for(j = 0; j < N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA)
      return 1;

    for(j = k; j < sig[OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}


/*************************************************
* Name:        poly_reduce
*
* Description: Inplace reduction of all coefficients of polynomial to
*              representative in [-6283009,6283007].
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_reduce(poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    a->coeffs[i] = reduce32(a->coeffs[i]);

  DBENCH_STOP(*tred);
}

/*************************************************
* Name:        poly_caddq
*
* Description: For all coefficients of in/out polynomial add Q if
*              coefficient is negative.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_caddq(poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N; ++i)
    a->coeffs[i] = caddq(a->coeffs[i]);

  DBENCH_STOP(*tred);
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
        poly_mult_karatsuba(&pC[0],&pA[0],&pB[0 ],n1,recursions-1);
        poly_sub(&pCC[0],&pCC[0],&pC[0],n0-1);
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


/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-ETA, ETA] by
*              performing rejection sampling on array of random bytes.
*
* Arguments:   - int32_t *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static unsigned int rej_eta(int32_t *a,
                            unsigned int len,
                            const uint8_t *buf,
                            unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;
  DBENCH_START();

  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

#if ETA == 2
    if(t0 < 15) {
      t0 = t0 - (205*t0 >> 10)*5;
      a[ctr++] = 2 - t0;
    }
    if(t1 < 15 && ctr < len) {
      t1 = t1 - (205*t1 >> 10)*5;
      a[ctr++] = 2 - t1;
    }
#elif ETA == 4
    if(t0 < 9)
      a[ctr++] = 4 - t0;
    if(t1 < 9 && ctr < len)
      a[ctr++] = 4 - t1;
#endif
  }

  DBENCH_STOP(*tsample);
  return ctr;
}

/*************************************************
* Name:        poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-ETA,ETA] by performing rejection sampling on the
*              output stream from SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
#if ETA == 2
#define POLY_UNIFORM_ETA_NBLOCKS ((136 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#elif ETA == 4
#define POLY_UNIFORM_ETA_NBLOCKS ((227 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#endif
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

/*************************************************
* Name:        poly_uniform_gamma1m1
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
*              of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const uint8_t seed[]: byte array with seed of length CRHBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
#define POLY_UNIFORM_GAMMA1_NBLOCKS ((POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
void poly_uniform_gamma1(poly *a,
                         const uint8_t seed[CRHBYTES],
                         uint16_t nonce)
{
  uint8_t buf[POLY_UNIFORM_GAMMA1_NBLOCKS*STREAM256_BLOCKBYTES];
  stream256_state state;

  stream256_init(&state, seed, nonce);
  stream256_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
  stream256_release(&state);
  polyz_unpack(a, buf);
}

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with TAU nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(seed).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const uint8_t mu[]: byte array containing seed of length SEEDBYTES
**************************************************/
void poly_challenge(poly *c, const uint8_t seed[SEEDBYTES]) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t buf[SHAKE256_RATE];
  shake256incctx state;

  shake256_inc_init(&state);
  shake256_inc_absorb(&state, seed, SEEDBYTES);
  shake256_inc_finalize(&state);
  shake256_squeezeblocks(buf, 1, &state);

  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)buf[i] << 8*i;
  pos = 8;

  for(i = 0; i < N; ++i)
    c->coeffs[i] = 0;
  for(i = N-TAU; i < N; ++i) {
    do {
      if(pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(buf, 1, &state);
        pos = 0;
      }

      b = buf[pos++];
    } while(b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2*(signs & 1);
    signs >>= 1;
  }
  shake256_inc_ctx_release(&state);
}

/*************************************************
* Name:        polyeta_pack
*
* Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYETA_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyeta_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint8_t t[8];
  DBENCH_START();

#if ETA == 2
  for(i = 0; i < N/8; ++i) {
    t[0] = ETA - a->coeffs[8*i+0];
    t[1] = ETA - a->coeffs[8*i+1];
    t[2] = ETA - a->coeffs[8*i+2];
    t[3] = ETA - a->coeffs[8*i+3];
    t[4] = ETA - a->coeffs[8*i+4];
    t[5] = ETA - a->coeffs[8*i+5];
    t[6] = ETA - a->coeffs[8*i+6];
    t[7] = ETA - a->coeffs[8*i+7];

    r[3*i+0]  = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[3*i+1]  = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[3*i+2]  = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
#elif ETA == 4
  for(i = 0; i < N/2; ++i) {
    t[0] = ETA - a->coeffs[2*i+0];
    t[1] = ETA - a->coeffs[2*i+1];
    r[i] = t[0] | (t[1] << 4);
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyeta_unpack
*
* Description: Unpack polynomial with coefficients in [-ETA,ETA].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyeta_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

#if ETA == 2
  for(i = 0; i < N/8; ++i) {
    r->coeffs[8*i+0] =  (a[3*i+0] >> 0) & 7;
    r->coeffs[8*i+1] =  (a[3*i+0] >> 3) & 7;
    r->coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7;
    r->coeffs[8*i+3] =  (a[3*i+1] >> 1) & 7;
    r->coeffs[8*i+4] =  (a[3*i+1] >> 4) & 7;
    r->coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7;
    r->coeffs[8*i+6] =  (a[3*i+2] >> 2) & 7;
    r->coeffs[8*i+7] =  (a[3*i+2] >> 5) & 7;

    r->coeffs[8*i+0] = ETA - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = ETA - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = ETA - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = ETA - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = ETA - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = ETA - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = ETA - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = ETA - r->coeffs[8*i+7];
  }
#elif ETA == 4
  for(i = 0; i < N/2; ++i) {
    r->coeffs[2*i+0] = a[i] & 0x0F;
    r->coeffs[2*i+1] = a[i] >> 4;
    r->coeffs[2*i+0] = ETA - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = ETA - r->coeffs[2*i+1];
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyt1_pack
*
* Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT1_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyt1_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/4; ++i) {
    r[5*i+0] = (a->coeffs[4*i+0] >> 0);
    r[5*i+1] = (a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2);
    r[5*i+2] = (a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4);
    r[5*i+3] = (a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6);
    r[5*i+4] = (a->coeffs[4*i+3] >> 2);
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyt1_unpack
*
* Description: Unpack polynomial t1 with 10-bit coefficients.
*              Output coefficients are standard representatives.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyt1_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/4; ++i) {
    r->coeffs[4*i+0] = ((a[5*i+0] >> 0) | ((uint32_t)a[5*i+1] << 8)) & 0x3FF;
    r->coeffs[4*i+1] = ((a[5*i+1] >> 2) | ((uint32_t)a[5*i+2] << 6)) & 0x3FF;
    r->coeffs[4*i+2] = ((a[5*i+2] >> 4) | ((uint32_t)a[5*i+3] << 4)) & 0x3FF;
    r->coeffs[4*i+3] = ((a[5*i+3] >> 6) | ((uint32_t)a[5*i+4] << 2)) & 0x3FF;
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyt0_pack
*
* Description: Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYT0_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyt0_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[8];
  DBENCH_START();

  for(i = 0; i < N/8; ++i) {
    t[0] = (1 << (D-1)) - a->coeffs[8*i+0];
    t[1] = (1 << (D-1)) - a->coeffs[8*i+1];
    t[2] = (1 << (D-1)) - a->coeffs[8*i+2];
    t[3] = (1 << (D-1)) - a->coeffs[8*i+3];
    t[4] = (1 << (D-1)) - a->coeffs[8*i+4];
    t[5] = (1 << (D-1)) - a->coeffs[8*i+5];
    t[6] = (1 << (D-1)) - a->coeffs[8*i+6];
    t[7] = (1 << (D-1)) - a->coeffs[8*i+7];

    r[13*i+ 0]  =  t[0];
    r[13*i+ 1]  =  t[0] >>  8;
    r[13*i+ 1] |=  t[1] <<  5;
    r[13*i+ 2]  =  t[1] >>  3;
    r[13*i+ 3]  =  t[1] >> 11;
    r[13*i+ 3] |=  t[2] <<  2;
    r[13*i+ 4]  =  t[2] >>  6;
    r[13*i+ 4] |=  t[3] <<  7;
    r[13*i+ 5]  =  t[3] >>  1;
    r[13*i+ 6]  =  t[3] >>  9;
    r[13*i+ 6] |=  t[4] <<  4;
    r[13*i+ 7]  =  t[4] >>  4;
    r[13*i+ 8]  =  t[4] >> 12;
    r[13*i+ 8] |=  t[5] <<  1;
    r[13*i+ 9]  =  t[5] >>  7;
    r[13*i+ 9] |=  t[6] <<  6;
    r[13*i+10]  =  t[6] >>  2;
    r[13*i+11]  =  t[6] >> 10;
    r[13*i+11] |=  t[7] <<  3;
    r[13*i+12]  =  t[7] >>  5;
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyt0_unpack
*
* Description: Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyt0_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

  for(i = 0; i < N/8; ++i) {
    r->coeffs[8*i+0]  = a[13*i+0];
    r->coeffs[8*i+0] |= (uint32_t)a[13*i+1] << 8;
    r->coeffs[8*i+0] &= 0x1FFF;

    r->coeffs[8*i+1]  = a[13*i+1] >> 5;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+2] << 3;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+3] << 11;
    r->coeffs[8*i+1] &= 0x1FFF;

    r->coeffs[8*i+2]  = a[13*i+3] >> 2;
    r->coeffs[8*i+2] |= (uint32_t)a[13*i+4] << 6;
    r->coeffs[8*i+2] &= 0x1FFF;

    r->coeffs[8*i+3]  = a[13*i+4] >> 7;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+5] << 1;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+6] << 9;
    r->coeffs[8*i+3] &= 0x1FFF;

    r->coeffs[8*i+4]  = a[13*i+6] >> 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+7] << 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+8] << 12;
    r->coeffs[8*i+4] &= 0x1FFF;

    r->coeffs[8*i+5]  = a[13*i+8] >> 1;
    r->coeffs[8*i+5] |= (uint32_t)a[13*i+9] << 7;
    r->coeffs[8*i+5] &= 0x1FFF;

    r->coeffs[8*i+6]  = a[13*i+9] >> 6;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+10] << 2;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+11] << 10;
    r->coeffs[8*i+6] &= 0x1FFF;

    r->coeffs[8*i+7]  = a[13*i+11] >> 3;
    r->coeffs[8*i+7] |= (uint32_t)a[13*i+12] << 5;
    r->coeffs[8*i+7] &= 0x1FFF;

    r->coeffs[8*i+0] = (1 << (D-1)) - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = (1 << (D-1)) - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = (1 << (D-1)) - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = (1 << (D-1)) - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = (1 << (D-1)) - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = (1 << (D-1)) - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = (1 << (D-1)) - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = (1 << (D-1)) - r->coeffs[8*i+7];
  }

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyz_pack
*
* Description: Bit-pack polynomial with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYZ_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyz_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[4];
  DBENCH_START();

#if GAMMA1 == (1 << 17)
  for(i = 0; i < N/4; ++i) {
    t[0] = GAMMA1 - a->coeffs[4*i+0];
    t[1] = GAMMA1 - a->coeffs[4*i+1];
    t[2] = GAMMA1 - a->coeffs[4*i+2];
    t[3] = GAMMA1 - a->coeffs[4*i+3];

    r[9*i+0]  = t[0];
    r[9*i+1]  = t[0] >> 8;
    r[9*i+2]  = t[0] >> 16;
    r[9*i+2] |= t[1] << 2;
    r[9*i+3]  = t[1] >> 6;
    r[9*i+4]  = t[1] >> 14;
    r[9*i+4] |= t[2] << 4;
    r[9*i+5]  = t[2] >> 4;
    r[9*i+6]  = t[2] >> 12;
    r[9*i+6] |= t[3] << 6;
    r[9*i+7]  = t[3] >> 2;
    r[9*i+8]  = t[3] >> 10;
  }
#elif GAMMA1 == (1 << 19)
  for(i = 0; i < N/2; ++i) {
    t[0] = GAMMA1 - a->coeffs[2*i+0];
    t[1] = GAMMA1 - a->coeffs[2*i+1];

    r[5*i+0]  = t[0];
    r[5*i+1]  = t[0] >> 8;
    r[5*i+2]  = t[0] >> 16;
    r[5*i+2] |= t[1] << 4;
    r[5*i+3]  = t[1] >> 4;
    r[5*i+4]  = t[1] >> 12;
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyz_unpack
*
* Description: Unpack polynomial z with coefficients
*              in [-(GAMMA1 - 1), GAMMA1].
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *a: byte array with bit-packed polynomial
**************************************************/
void polyz_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
  DBENCH_START();

#if GAMMA1 == (1 << 17)
  for(i = 0; i < N/4; ++i) {
    r->coeffs[4*i+0]  = a[9*i+0];
    r->coeffs[4*i+0] |= (uint32_t)a[9*i+1] << 8;
    r->coeffs[4*i+0] |= (uint32_t)a[9*i+2] << 16;
    r->coeffs[4*i+0] &= 0x3FFFF;

    r->coeffs[4*i+1]  = a[9*i+2] >> 2;
    r->coeffs[4*i+1] |= (uint32_t)a[9*i+3] << 6;
    r->coeffs[4*i+1] |= (uint32_t)a[9*i+4] << 14;
    r->coeffs[4*i+1] &= 0x3FFFF;

    r->coeffs[4*i+2]  = a[9*i+4] >> 4;
    r->coeffs[4*i+2] |= (uint32_t)a[9*i+5] << 4;
    r->coeffs[4*i+2] |= (uint32_t)a[9*i+6] << 12;
    r->coeffs[4*i+2] &= 0x3FFFF;

    r->coeffs[4*i+3]  = a[9*i+6] >> 6;
    r->coeffs[4*i+3] |= (uint32_t)a[9*i+7] << 2;
    r->coeffs[4*i+3] |= (uint32_t)a[9*i+8] << 10;
    r->coeffs[4*i+3] &= 0x3FFFF;

    r->coeffs[4*i+0] = GAMMA1 - r->coeffs[4*i+0];
    r->coeffs[4*i+1] = GAMMA1 - r->coeffs[4*i+1];
    r->coeffs[4*i+2] = GAMMA1 - r->coeffs[4*i+2];
    r->coeffs[4*i+3] = GAMMA1 - r->coeffs[4*i+3];
  }
#elif GAMMA1 == (1 << 19)
  for(i = 0; i < N/2; ++i) {
    r->coeffs[2*i+0]  = a[5*i+0];
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+1] << 8;
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+2] << 16;
    r->coeffs[2*i+0] &= 0xFFFFF;

    r->coeffs[2*i+1]  = a[5*i+2] >> 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+3] << 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+4] << 12;
    r->coeffs[2*i+0] &= 0xFFFFF;

    r->coeffs[2*i+0] = GAMMA1 - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = GAMMA1 - r->coeffs[2*i+1];
  }
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
* Name:        polyw1_pack
*
* Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
*              Input coefficients are assumed to be standard representatives.
*
* Arguments:   - uint8_t *r: pointer to output byte array with at least
*                            POLYW1_PACKEDBYTES bytes
*              - const poly *a: pointer to input polynomial
**************************************************/
void polyw1_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  DBENCH_START();

#if GAMMA2 == (Q-1)/88
  for(i = 0; i < N/4; ++i) {
    r[3*i+0]  = a->coeffs[4*i+0];
    r[3*i+0] |= a->coeffs[4*i+1] << 6;
    r[3*i+1]  = a->coeffs[4*i+1] >> 2;
    r[3*i+1] |= a->coeffs[4*i+2] << 4;
    r[3*i+2]  = a->coeffs[4*i+2] >> 4;
    r[3*i+2] |= a->coeffs[4*i+3] << 2;
  }
#elif GAMMA2 == (Q-1)/32
  for(i = 0; i < N/2; ++i)
    r[i] = a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4);
#endif

  DBENCH_STOP(*tpack);
}

/*************************************************
Name: poly_binary_mult
Description: 二元多項式の乗算を行う関数。入力された多項式 a に対し、
         入力されたバイナリ配列 pA の要素が1の場合は b を加算し、
         -1の場合は b を減算する。
         出力はバイナリ配列 pC に格納される。
Arguments: - uint32_t* pC: 出力されるバイナリ配列の先頭アドレス
                       長さは k*n*sizeof(uint32_t) byte 以上
         - unsigned char* pA: 入力バイナリ配列の先頭アドレス
         - uint32_t* pB: 乗算するバイナリ配列の先頭アドレス
         - size_t n: 多項式の次数（1つの要素の長さ）
         - size_t k: 配列の数
**************************************************/


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

static inline uint32_t br_dec32le(const uint8_t *src)
{
    return (uint32_t)src[0]
        | ((uint32_t)src[1] << 8)
        | ((uint32_t)src[2] << 16)
        | ((uint32_t)src[3] << 24);
}

static void br_range_dec32le(uint32_t *v, size_t num, const uint8_t *src)
{
    while (num-- > 0) {
        *v ++ = br_dec32le(src);
        src += 4;
    }
}

static inline uint32_t br_swap32(uint32_t x)
{
    x = ((x & (uint32_t)0x00FF00FF) << 8)
        | ((x >> 8) & (uint32_t)0x00FF00FF);
    return (x << 16) | (x >> 16);
}

static inline void br_enc32le(uint8_t *dst, uint32_t x)
{
    dst[0] = (uint8_t)x;
    dst[1] = (uint8_t)(x >> 8);
    dst[2] = (uint8_t)(x >> 16);
    dst[3] = (uint8_t)(x >> 24);
}

static void br_range_enc32le(uint8_t *dst, const uint32_t *v, size_t num)
{
    while (num-- > 0) {
        br_enc32le(dst, *v ++);
        dst += 4;
    }
}

static void br_aes_ct64_bitslice_Sbox(uint64_t *q)
{
    /*
     * This S-box implementation is a straightforward translation of
     * the circuit described by Boyar and Peralta in "A new
     * combinational logic minimization technique with applications
     * to cryptology" (https://eprint.iacr.org/2009/191.pdf).
     *
     * Note that variables x* (input) and s* (output) are numbered
     * in "reverse" order (x0 is the high bit, x7 is the low bit).
     */

    uint64_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint64_t y1, y2, y3, y4, y5, y6, y7, y8, y9;
    uint64_t y10, y11, y12, y13, y14, y15, y16, y17, y18, y19;
    uint64_t y20, y21;
    uint64_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9;
    uint64_t z10, z11, z12, z13, z14, z15, z16, z17;
    uint64_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint64_t t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
    uint64_t t20, t21, t22, t23, t24, t25, t26, t27, t28, t29;
    uint64_t t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
    uint64_t t40, t41, t42, t43, t44, t45, t46, t47, t48, t49;
    uint64_t t50, t51, t52, t53, t54, t55, t56, t57, t58, t59;
    uint64_t t60, t61, t62, t63, t64, t65, t66, t67;
    uint64_t s0, s1, s2, s3, s4, s5, s6, s7;

    x0 = q[7];
    x1 = q[6];
    x2 = q[5];
    x3 = q[4];
    x4 = q[3];
    x5 = q[2];
    x6 = q[1];
    x7 = q[0];

    /*
     * Top linear transformation.
     */
    y14 = x3 ^ x5;
    y13 = x0 ^ x6;
    y9 = x0 ^ x3;
    y8 = x0 ^ x5;
    t0 = x1 ^ x2;
    y1 = t0 ^ x7;
    y4 = y1 ^ x3;
    y12 = y13 ^ y14;
    y2 = y1 ^ x0;
    y5 = y1 ^ x6;
    y3 = y5 ^ y8;
    t1 = x4 ^ y12;
    y15 = t1 ^ x5;
    y20 = t1 ^ x1;
    y6 = y15 ^ x7;
    y10 = y15 ^ t0;
    y11 = y20 ^ y9;
    y7 = x7 ^ y11;
    y17 = y10 ^ y11;
    y19 = y10 ^ y8;
    y16 = t0 ^ y11;
    y21 = y13 ^ y16;
    y18 = x0 ^ y16;

    /*
     * Non-linear section.
     */
    t2 = y12 & y15;
    t3 = y3 & y6;
    t4 = t3 ^ t2;
    t5 = y4 & x7;
    t6 = t5 ^ t2;
    t7 = y13 & y16;
    t8 = y5 & y1;
    t9 = t8 ^ t7;
    t10 = y2 & y7;
    t11 = t10 ^ t7;
    t12 = y9 & y11;
    t13 = y14 & y17;
    t14 = t13 ^ t12;
    t15 = y8 & y10;
    t16 = t15 ^ t12;
    t17 = t4 ^ t14;
    t18 = t6 ^ t16;
    t19 = t9 ^ t14;
    t20 = t11 ^ t16;
    t21 = t17 ^ y20;
    t22 = t18 ^ y19;
    t23 = t19 ^ y21;
    t24 = t20 ^ y18;

    t25 = t21 ^ t22;
    t26 = t21 & t23;
    t27 = t24 ^ t26;
    t28 = t25 & t27;
    t29 = t28 ^ t22;
    t30 = t23 ^ t24;
    t31 = t22 ^ t26;
    t32 = t31 & t30;
    t33 = t32 ^ t24;
    t34 = t23 ^ t33;
    t35 = t27 ^ t33;
    t36 = t24 & t35;
    t37 = t36 ^ t34;
    t38 = t27 ^ t36;
    t39 = t29 & t38;
    t40 = t25 ^ t39;

    t41 = t40 ^ t37;
    t42 = t29 ^ t33;
    t43 = t29 ^ t40;
    t44 = t33 ^ t37;
    t45 = t42 ^ t41;
    z0 = t44 & y15;
    z1 = t37 & y6;
    z2 = t33 & x7;
    z3 = t43 & y16;
    z4 = t40 & y1;
    z5 = t29 & y7;
    z6 = t42 & y11;
    z7 = t45 & y17;
    z8 = t41 & y10;
    z9 = t44 & y12;
    z10 = t37 & y3;
    z11 = t33 & y4;
    z12 = t43 & y13;
    z13 = t40 & y5;
    z14 = t29 & y2;
    z15 = t42 & y9;
    z16 = t45 & y14;
    z17 = t41 & y8;

    /*
     * Bottom linear transformation.
     */
    t46 = z15 ^ z16;
    t47 = z10 ^ z11;
    t48 = z5 ^ z13;
    t49 = z9 ^ z10;
    t50 = z2 ^ z12;
    t51 = z2 ^ z5;
    t52 = z7 ^ z8;
    t53 = z0 ^ z3;
    t54 = z6 ^ z7;
    t55 = z16 ^ z17;
    t56 = z12 ^ t48;
    t57 = t50 ^ t53;
    t58 = z4 ^ t46;
    t59 = z3 ^ t54;
    t60 = t46 ^ t57;
    t61 = z14 ^ t57;
    t62 = t52 ^ t58;
    t63 = t49 ^ t58;
    t64 = z4 ^ t59;
    t65 = t61 ^ t62;
    t66 = z1 ^ t63;
    s0 = t59 ^ t63;
    s6 = t56 ^ ~t62;
    s7 = t48 ^ ~t60;
    t67 = t64 ^ t65;
    s3 = t53 ^ t66;
    s4 = t51 ^ t66;
    s5 = t47 ^ t65;
    s1 = t64 ^ ~s3;
    s2 = t55 ^ ~t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

static void br_aes_ct64_ortho(uint64_t *q)
{
#define SWAPN(cl, ch, s, x, y)   do { \
        uint64_t a, b; \
        a = (x); \
        b = (y); \
        (x) = (a & (uint64_t)cl) | ((b & (uint64_t)cl) << (s)); \
        (y) = ((a & (uint64_t)ch) >> (s)) | (b & (uint64_t)ch); \
    } while (0)

#define SWAP2(x, y)    SWAPN(0x5555555555555555, 0xAAAAAAAAAAAAAAAA,  1, x, y)
#define SWAP4(x, y)    SWAPN(0x3333333333333333, 0xCCCCCCCCCCCCCCCC,  2, x, y)
#define SWAP8(x, y)    SWAPN(0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0,  4, x, y)

    SWAP2(q[0], q[1]);
    SWAP2(q[2], q[3]);
    SWAP2(q[4], q[5]);
    SWAP2(q[6], q[7]);

    SWAP4(q[0], q[2]);
    SWAP4(q[1], q[3]);
    SWAP4(q[4], q[6]);
    SWAP4(q[5], q[7]);

    SWAP8(q[0], q[4]);
    SWAP8(q[1], q[5]);
    SWAP8(q[2], q[6]);
    SWAP8(q[3], q[7]);
}

static void br_aes_ct64_interleave_in(uint64_t *q0, uint64_t *q1, const uint32_t *w)
{
    uint64_t x0, x1, x2, x3;

    x0 = w[0];
    x1 = w[1];
    x2 = w[2];
    x3 = w[3];
    x0 |= (x0 << 16);
    x1 |= (x1 << 16);
    x2 |= (x2 << 16);
    x3 |= (x3 << 16);
    x0 &= (uint64_t)0x0000FFFF0000FFFF;
    x1 &= (uint64_t)0x0000FFFF0000FFFF;
    x2 &= (uint64_t)0x0000FFFF0000FFFF;
    x3 &= (uint64_t)0x0000FFFF0000FFFF;
    x0 |= (x0 << 8);
    x1 |= (x1 << 8);
    x2 |= (x2 << 8);
    x3 |= (x3 << 8);
    x0 &= (uint64_t)0x00FF00FF00FF00FF;
    x1 &= (uint64_t)0x00FF00FF00FF00FF;
    x2 &= (uint64_t)0x00FF00FF00FF00FF;
    x3 &= (uint64_t)0x00FF00FF00FF00FF;
    *q0 = x0 | (x2 << 8);
    *q1 = x1 | (x3 << 8);
}

static void br_aes_ct64_interleave_out(uint32_t *w, uint64_t q0, uint64_t q1)
{
    uint64_t x0, x1, x2, x3;

    x0 = q0 & (uint64_t)0x00FF00FF00FF00FF;
    x1 = q1 & (uint64_t)0x00FF00FF00FF00FF;
    x2 = (q0 >> 8) & (uint64_t)0x00FF00FF00FF00FF;
    x3 = (q1 >> 8) & (uint64_t)0x00FF00FF00FF00FF;
    x0 |= (x0 >> 8);
    x1 |= (x1 >> 8);
    x2 |= (x2 >> 8);
    x3 |= (x3 >> 8);
    x0 &= (uint64_t)0x0000FFFF0000FFFF;
    x1 &= (uint64_t)0x0000FFFF0000FFFF;
    x2 &= (uint64_t)0x0000FFFF0000FFFF;
    x3 &= (uint64_t)0x0000FFFF0000FFFF;
    w[0] = (uint32_t)x0 | (uint32_t)(x0 >> 16);
    w[1] = (uint32_t)x1 | (uint32_t)(x1 >> 16);
    w[2] = (uint32_t)x2 | (uint32_t)(x2 >> 16);
    w[3] = (uint32_t)x3 | (uint32_t)(x3 >> 16);
}

static const uint8_t Rcon[] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

static uint32_t sub_word(uint32_t x)
{
    uint64_t q[8];

    memset(q, 0, sizeof q);
    q[0] = x;
    br_aes_ct64_ortho(q);
    br_aes_ct64_bitslice_Sbox(q);
    br_aes_ct64_ortho(q);
    return (uint32_t)q[0];
}

static void br_aes_ct64_keysched(uint64_t *comp_skey, const uint8_t *key)
{
    int i, j, k, nk, nkf;
    uint32_t tmp;
    uint32_t skey[60];

    int key_len = 32;

    nk = (int)(key_len >> 2);
    nkf = (int)((14 + 1) << 2);
    br_range_dec32le(skey, (key_len >> 2), key);
    tmp = skey[(key_len >> 2) - 1];
    for (i = nk, j = 0, k = 0; i < nkf; i ++) {
        if (j == 0) {
            tmp = (tmp << 24) | (tmp >> 8);
            tmp = sub_word(tmp) ^ Rcon[k];
        } else if (nk > 6 && j == 4) {
            tmp = sub_word(tmp);
        }
        tmp ^= skey[i - nk];
        skey[i] = tmp;
        if (++ j == nk) {
            j = 0;
            k ++;
        }
    }

    for (i = 0, j = 0; i < nkf; i += 4, j += 2) {
        uint64_t q[8];

        br_aes_ct64_interleave_in(&q[0], &q[4], skey + i);
        q[1] = q[0];
        q[2] = q[0];
        q[3] = q[0];
        q[5] = q[4];
        q[6] = q[4];
        q[7] = q[4];
        br_aes_ct64_ortho(q);
        comp_skey[j + 0] =
              (q[0] & (uint64_t)0x1111111111111111)
            | (q[1] & (uint64_t)0x2222222222222222)
            | (q[2] & (uint64_t)0x4444444444444444)
            | (q[3] & (uint64_t)0x8888888888888888);
        comp_skey[j + 1] =
              (q[4] & (uint64_t)0x1111111111111111)
            | (q[5] & (uint64_t)0x2222222222222222)
            | (q[6] & (uint64_t)0x4444444444444444)
            | (q[7] & (uint64_t)0x8888888888888888);
    }
}

static void br_aes_ct64_skey_expand(uint64_t *skey, const uint64_t *comp_skey)
{
    unsigned u, v, n;

    n = (14 + 1) << 1;
    for (u = 0, v = 0; u < n; u ++, v += 4) {
        uint64_t x0, x1, x2, x3;

        x0 = x1 = x2 = x3 = comp_skey[u];
        x0 &= (uint64_t)0x1111111111111111;
        x1 &= (uint64_t)0x2222222222222222;
        x2 &= (uint64_t)0x4444444444444444;
        x3 &= (uint64_t)0x8888888888888888;
        x1 >>= 1;
        x2 >>= 2;
        x3 >>= 3;
        skey[v + 0] = (x0 << 4) - x0;
        skey[v + 1] = (x1 << 4) - x1;
        skey[v + 2] = (x2 << 4) - x2;
        skey[v + 3] = (x3 << 4) - x3;
    }
}

static inline void add_round_key(uint64_t *q, const uint64_t *sk)
{
    q[0] ^= sk[0];
    q[1] ^= sk[1];
    q[2] ^= sk[2];
    q[3] ^= sk[3];
    q[4] ^= sk[4];
    q[5] ^= sk[5];
    q[6] ^= sk[6];
    q[7] ^= sk[7];
}

static inline void shift_rows(uint64_t *q)
{
    int i;

    for (i = 0; i < 8; i ++) {
        uint64_t x;

        x = q[i];
        q[i] = (x & (uint64_t)0x000000000000FFFF)
            | ((x & (uint64_t)0x00000000FFF00000) >> 4)
            | ((x & (uint64_t)0x00000000000F0000) << 12)
            | ((x & (uint64_t)0x0000FF0000000000) >> 8)
            | ((x & (uint64_t)0x000000FF00000000) << 8)
            | ((x & (uint64_t)0xF000000000000000) >> 12)
            | ((x & (uint64_t)0x0FFF000000000000) << 4);
    }
}

static inline uint64_t rotr32(uint64_t x)
{
    return (x << 32) | (x >> 32);
}

static inline void mix_columns(uint64_t *q)
{
    uint64_t q0, q1, q2, q3, q4, q5, q6, q7;
    uint64_t r0, r1, r2, r3, r4, r5, r6, r7;

    q0 = q[0];
    q1 = q[1];
    q2 = q[2];
    q3 = q[3];
    q4 = q[4];
    q5 = q[5];
    q6 = q[6];
    q7 = q[7];
    r0 = (q0 >> 16) | (q0 << 48);
    r1 = (q1 >> 16) | (q1 << 48);
    r2 = (q2 >> 16) | (q2 << 48);
    r3 = (q3 >> 16) | (q3 << 48);
    r4 = (q4 >> 16) | (q4 << 48);
    r5 = (q5 >> 16) | (q5 << 48);
    r6 = (q6 >> 16) | (q6 << 48);
    r7 = (q7 >> 16) | (q7 << 48);

    q[0] = q7 ^ r7 ^ r0 ^ rotr32(q0 ^ r0);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr32(q1 ^ r1);
    q[2] = q1 ^ r1 ^ r2 ^ rotr32(q2 ^ r2);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr32(q3 ^ r3);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr32(q4 ^ r4);
    q[5] = q4 ^ r4 ^ r5 ^ rotr32(q5 ^ r5);
    q[6] = q5 ^ r5 ^ r6 ^ rotr32(q6 ^ r6);
    q[7] = q6 ^ r6 ^ r7 ^ rotr32(q7 ^ r7);
}

static void inc4_be(uint32_t *x)
{
  *x = br_swap32(*x)+4;
  *x = br_swap32(*x);
}

static void aes_ctr4x(uint8_t out[64], uint32_t ivw[16], uint64_t sk_exp[120])
{
  uint32_t w[16];
  uint64_t q[8];
  int i;

  memcpy(w, ivw, sizeof(w));
  for (i = 0; i < 4; i++) {
    br_aes_ct64_interleave_in(&q[i], &q[i + 4], w + (i << 2));
  }
  br_aes_ct64_ortho(q);

  add_round_key(q, sk_exp);
  for (i = 1; i < 14; i++) {
    br_aes_ct64_bitslice_Sbox(q);
    shift_rows(q);
    mix_columns(q);
    add_round_key(q, sk_exp + (i << 3));
  }
  br_aes_ct64_bitslice_Sbox(q);
  shift_rows(q);
  add_round_key(q, sk_exp + 112);

  br_aes_ct64_ortho(q);
  for (i = 0; i < 4; i ++) {
    br_aes_ct64_interleave_out(w + (i << 2), q[i], q[i + 4]);
  }
  br_range_enc32le(out, w, 16);

  /* Increase counter for next 4 blocks */
  inc4_be(ivw+3);
  inc4_be(ivw+7);
  inc4_be(ivw+11);
  inc4_be(ivw+15);
}

static void br_aes_ct64_ctr_init(uint64_t sk_exp[120], const uint8_t *key)
{
    uint64_t skey[30];

    br_aes_ct64_keysched(skey, key);
    br_aes_ct64_skey_expand(sk_exp, skey);
}

void aes256ctr_init(aes256ctr_ctx *s, const uint8_t key[32], const uint8_t nonce[12])
{
  br_aes_ct64_ctr_init(s->sk_exp, key);

  br_range_dec32le(s->ivw, 3, nonce);
  memcpy(s->ivw +  4, s->ivw, 3 * sizeof(uint32_t));
  memcpy(s->ivw +  8, s->ivw, 3 * sizeof(uint32_t));
  memcpy(s->ivw + 12, s->ivw, 3 * sizeof(uint32_t));
  s->ivw[ 3] = br_swap32(0);
  s->ivw[ 7] = br_swap32(1);
  s->ivw[11] = br_swap32(2);
  s->ivw[15] = br_swap32(3);
}

void aes256ctr_squeezeblocks(uint8_t *out, size_t nblocks, aes256ctr_ctx *s)
{
  while (nblocks > 0) {
    aes_ctr4x(out, s->ivw, s->sk_exp);
    out += 64;
    nblocks--;
  }
}
