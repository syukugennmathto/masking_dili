#include "noise.h"
#include "random.h"
#include "../dilithium/params.h"

#define BLOCKS 3

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

void small_bounded_noise_generation_256(poly *out_buffer, unsigned char* seed, unsigned char nonce) {
    const size_t SEEDBYTES = 32;
    unsigned int i, ctr;
    unsigned char inbuf[SEEDBYTES + 1];
    unsigned char outbuf[2 * SHAKE256_RATE];
    uint64_t state[25];

    for (i = 0; i < SEEDBYTES; ++i)
        inbuf[i] = seed[i];
    inbuf[SEEDBYTES] = nonce;

    shake256_absorb(state, inbuf, SEEDBYTES + 1);
    shake256_squeezeblocks(outbuf, 2, state);

    ctr = rej_eta(out_buffer->coeffs, N, outbuf, 2 * SHAKE256_RATE);

    if (ctr < N) {
        shake256_squeezeblocks(outbuf, 1, state);
        rej_eta(out_buffer->coeffs + ctr, N - ctr, outbuf, SHAKE256_RATE);
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
