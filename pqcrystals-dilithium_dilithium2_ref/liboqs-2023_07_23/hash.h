#ifndef _HASH_H_
#define _HASH_H_

#include <stdint.h>
#include <string.h>

void hash_init(unsigned char*state);
void hash_absorb(unsigned char* state, uint32_t* in, size_t len);
void hash_gen(unsigned char *output, unsigned char *state);
void H(unsigned char* c, unsigned char* rho, uint32_t* t1, uint32_t* w1);

#endif // _HASH_H_
