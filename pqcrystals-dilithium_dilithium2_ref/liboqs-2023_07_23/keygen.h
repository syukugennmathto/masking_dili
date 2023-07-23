#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keygen(uint8_t *pk, uint8_t *sk);


#endif
