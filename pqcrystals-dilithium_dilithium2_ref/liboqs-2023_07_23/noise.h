#ifndef _NOISE_H_
#define _NOISE_H_

#include "random.h"
#include "fips202.h"

#include <stdint.h>
#include <stdlib.h>

void sam(uint32_t* out_buffer, unsigned char *seed);
uint32_t small_noise_rejection_256         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     small_bounded_noise_generation_256(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);
uint32_t large_noise_rejection_256         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     large_bounded_noise_generation_256(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);

uint32_t small_noise_rejection         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     small_bounded_noise_generation(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);
uint32_t large_noise_rejection         (uint32_t* out_buffer, size_t out_len, unsigned char* buffer, size_t in_len);
void     large_bounded_noise_generation(uint32_t* out_buffer, unsigned char* seed, unsigned char nonce);

#endif // _NOISE_H_
