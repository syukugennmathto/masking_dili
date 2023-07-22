#include <stdio.h>
#include <stdint.h>
#include "params.h"
#include "rounding.h"

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
int32_t decompose(int32_t *a0, int32_t a) {
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask >> 1) + 1;
    uint32_t a0_unsigned, a1_unsigned;

    // Convert to unsigned 32-bit integers for intermediate calculations
    uint32_t a_unsigned = (uint32_t)a;

    // Calculate a1 and a0 in unsigned format
    a1_unsigned = (a_unsigned + 127) >> 7;
#if GAMMA2 == (Q-1)/32
    a1_unsigned = (a1_unsigned * 1025 + (1 << 21)) >> 22;
    a1_unsigned &= 15;
#elif GAMMA2 == (Q-1)/88
    a1_unsigned = (a1_unsigned * 11275 + (1 << 23)) >> 24;
    a1_unsigned ^= ((43 - a1_unsigned) >> 31) & a1_unsigned;
#endif

    a0_unsigned = a_unsigned - a1_unsigned * 2 * GAMMA2;
    a0_unsigned -= (((Q - 1) / 2 - a0_unsigned) >> 31) & Q;

    // Convert back to signed 32-bit integer format
    *a0 = (int32_t)a0_unsigned;

    // Convert a1 back to signed 32-bit integer format and return it
    return (int32_t)a1_unsigned;
}

/*************************************************
* Name:        make_hint
*
* Description: Compute hint bit indicating whether the low bits of the
*              input element overflow into the high bits.
*
* Arguments:   - int32_t a0: low bits of input element
*              - int32_t a1: high bits of input element
*
* Returns 1 if overflow.
**************************************************/
unsigned int make_hint(int32_t a0, int32_t a1) {
    
    uint32_t r1, v1;
    uint32_t mask = (1 << D) - 1;
    uint32_t d_1 = (mask >> 1) + 1;
    uint32_t a0_unsigned = (uint32_t)a0;
    uint32_t a1_unsigned = (uint32_t)a1;

    highbits(&r1, a0_unsigned, D);
    highbits(&v1, a0_unsigned + a1_unsigned, D);

    if (r1 == v1) {
        return 0;
    } else {
        return 1;
    }
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
int32_t use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1;

  a1 = decompose(&a0, a);
  if(hint == 0)
    return a1;

#if GAMMA2 == (Q-1)/32
  if(a0 > 0)
    return (a1 + 1) & 15;
  else
    return (a1 - 1) & 15;
#elif GAMMA2 == (Q-1)/88
  if(a0 > 0)
    return (a1 == 43) ?  0 : a1 + 1;
  else
    return (a1 ==  0) ? 43 : a1 - 1;
#endif
}


/*************************************************
* Name:        highbits
*
* Description: Compute the high bits of a finite field element `r` given a base value.
*              The base value determines the number of bits to shift the element `r` to the right.
*
* Arguments:   - uint32_t *r1: pointer to the output high bits of `r`
*              - uint32_t r: input element
*              - uint32_t base: base value used for shifting `r`
**************************************************/
void highbits(uint32_t *r1, uint32_t r, uint32_t base) {
    uint32_t mask = (1 << base) - 1;
    uint32_t d_1 = (mask >> 1) + 1;
    *r1 = (r + d_1) >> base;
}
