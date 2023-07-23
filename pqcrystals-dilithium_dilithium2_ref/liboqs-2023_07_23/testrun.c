#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "params.h"
#include "signature.h"
#include "keygen.h"
#include "verify.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

#include <stdio.h>
#include <stdlib.h>

int test_func()
{
    
    uint8_t *sm;
    size_t smlen;
    uint8_t *m;
    size_t mlen;
    uint8_t *sk;
    size_t sklen;
    uint8_t *pk;
    
    
    

    crypto_sign_keygen(pk,sk);
    crypto_sign(sm,&smlen,m,mlen,sk);
    if(crypto_sign_verify(sk,sklen,m,mlen,pk))
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
