#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#define SHAKE128_RATE 168
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))
#define NROUNDS 24
#define BLOCKS 3





void hash_init(unsigned char*state);
void hash_absorb(unsigned char* state, uint32_t* in, size_t len);
void hash_gen(uint32_t* output, unsigned char *state);
void H(uint32_t* c, uint32_t* rho, uint32_t* t1, uint32_t* w1);
__attribute__((always_inline)) static uint32_t lfsr_inc_32();
void sam(uint32_t* out_buffer, uint32_t *seed);
void shake128(unsigned char *output,
              unsigned long long outlen,
              uint32_t *input,
              unsigned long long inlen);
void shake128_absorb(uint64_t *s,
                      uint32_t *input,
                     unsigned long long inlen);

void shake128_squeezeblocks(unsigned char *output,
                            unsigned long nblocks,
                            uint64_t *s);
static void keccak_absorb(uint64_t *s,
                   unsigned int r,
                          uint32_t *m,
                   unsigned long long mlen,
                   unsigned char p);
static uint64_t load64(uint32_t *x);
void KeccakF1600_StatePermute(uint64_t *state);
static const uint64_t KeccakF_RoundConstants[NROUNDS];
static void keccak_squeezeblocks(unsigned char *h,
                                 unsigned long nblocks,
                                 uint64_t *s,
                                 unsigned int r);
static void store64(unsigned char *x, uint64_t u);
int main_2();

int main(void)
{
    uint32_t rounds = 0;
    uint32_t A [A__len];
    uint32_t t [t__len],t0[t__len];
    uint32_t t1[t__len];
    uint32_t s1[s1_len],s2[s2_len];
    uint32_t y [y__len],w [w__len],w1[w__len],z  [z__len];
    uint32_t r [r__len],r0[r__len],r1[r__len],ct0[t__len];
    
    uint32_t rho[32],rhoprime[32+48],c[c__len],h[t__len];
    for (uint32_t i =0 ; i<8; i++) {
        ((uint32_t*)rho)[i] = 3;
    }
    sam(A,rho);
    
    for(uint32_t i = 0; i < t__len; ++i){
        t1[i] = 2^(i%10);

    }
    for(uint32_t i = 0; i < w__len; ++i){ w1[i] = 2^((i+1) %10);
    }
    H(c,rho,t1,w1);
    
    printf("this is c\n");
    for(uint32_t i = 0; i < c__len; ++i) {printf("%u,",c[i]);
        if (i % 10 == 0){
            printf("\n");
        }
        
    }
    printf("\n");
    printf("this is rho\n");
    for(uint32_t i = 0; i < 32; ++i) printf("%u,",rho[i]);
    printf("\n");
    printf("this is t\n");
    for(uint32_t i = 0; i < t__len; ++i) {printf("%u,",t1[i]);
        if (i % 10 == 0){
            printf("\n");
        }
        
    }
    printf("\n");
    printf("this is w\n");
    for(uint32_t i = 0; i < w__len; ++i){ printf("%u,",w1[i]);
        if (i % 10 == 0){
            printf("\n");
        }
    }
    printf("\n");
}

int main_2(){
    uint32_t A[256*5*4];
    uint32_t rho[32];
    /*printf("first \n");*/
    for (uint32_t i =0 ; i<8; i++) {
        ((uint32_t*)rho)[i] = 3;
    }
   /* for (uint32_t i =0 ; i<32; i++) {
        printf("%u is rho[%d] \n",rho[i],i);
        
    }
    printf("second \n");*/
    sam(A,rho);
/*    for (uint32_t i =0 ; i<32; i++) {
        printf("%u is rho[%d] \n",rho[i],i);
        
    }*/
    for (uint32_t i =0 ; i<256*5*4; i++){
        if (i % 10 == 0) {
            printf("\n");
        }
        printf("%u,",A[i]);
    }
    return 0;
}

static uint32_t lfsr_inc_32()
{
    uint32_t tap = 0;
    int i = 1;
    const uint32_t lfsr_taps32[] = {0xFFFFFFFF, (1 << 31), (1 << 21), (1 << 1), (1 << 0), 0};
    uint32_t lfsr_state = 1;
    
    while(lfsr_taps32[i])
        tap ^= !!(lfsr_taps32[i++] & lfsr_state);
    lfsr_state <<= 1;
    printf("on1line %d is lfsr_state\n",lfsr_state);
    lfsr_state |= tap;
    printf("on2line %d is lfsr_state\n",lfsr_state);
    lfsr_state &= lfsr_taps32[0];
    printf("on3ine %d is lfsr_state\n",lfsr_state);
    
    
    printf("finally %d is lfsr_state\n",lfsr_state);
    return 0;
}


void sam(uint32_t* out_buffer,uint32_t *seed) /// len in 32 bits
{
    unsigned char* it = (unsigned char*)out_buffer;
    shake128(it,256*5*4*sizeof(uint32_t),seed,32);
    
}
void shake128(unsigned char *output,
              unsigned long long outlen,
              uint32_t *input,
              unsigned long long inlen)
{
  unsigned int i;
  unsigned long nblocks = outlen/SHAKE128_RATE;
  unsigned char t[SHAKE128_RATE];
  uint64_t s[25];

  shake128_absorb(s, input, inlen);
  shake128_squeezeblocks(output, nblocks, s);

  output += nblocks*SHAKE128_RATE;
  outlen -= nblocks*SHAKE128_RATE;

  if(outlen) {
    shake128_squeezeblocks(t, 1, s);
    for(i = 0; i < outlen; ++i)
      output[i] = t[i];
  }
}

void shake128_squeezeblocks(unsigned char *output,
                            unsigned long nblocks,
                            uint64_t *s)
{
  keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);
}
static void keccak_squeezeblocks(unsigned char *h,
                                 unsigned long nblocks,
                                 uint64_t *s,
                                 unsigned int r)
{
  unsigned int i;

  while(nblocks > 0) {
    KeccakF1600_StatePermute(s);
    for(i=0; i < (r >> 3); i++) {
      store64(h + 8*i, s[i]);
    }
    h += r;
    --nblocks;
  }
}

void shake128_absorb(uint64_t *s,
                     uint32_t *input,
                     unsigned long long inlen)
{
  keccak_absorb(s, 168, input, inlen, 0x1F);
}

static void keccak_absorb(uint64_t *s,
                          unsigned int r,
                          uint32_t *m,
                          unsigned long long mlen,
                          unsigned char p)
{
  unsigned int i;
  unsigned char t[200];

  for(i = 0; i < 25; ++i)
    s[i] = 0;

  while(mlen >= r) {
    for(i = 0; i < r/8; ++i)
        s[i] ^= load64((uint32_t *)(t + 8*i));


    KeccakF1600_StatePermute(s);
    mlen -= r;
    m += r;
  }

  for(i = 0; i < r; ++i)
    t[i] = 0;
  for(i = 0; i < mlen; ++i)
    t[i] = m[i];
  t[i] = p;
  t[r-1] |= 128;
  for(i = 0; i < r/8; ++i)
      s[i] ^= load64((uint32_t *)(t + 8*i));

}

static uint64_t load64(uint32_t *x){
  unsigned int i;
  uint64_t r = 0;

  for (i = 0; i < 8; ++i)
    r |= (uint64_t)x[i] << 8*i;

  return r;
}
static void store64(unsigned char *x, uint64_t u) {
  unsigned int i;

  for(i = 0; i < 8; ++i)
    x[i] = u >> 8*i;
}

static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};

void KeccakF1600_StatePermute(uint64_t *state)
{
        int round;

        uint64_t Aba, Abe, Abi, Abo, Abu;
        uint64_t Aga, Age, Agi, Ago, Agu;
        uint64_t Aka, Ake, Aki, Ako, Aku;
        uint64_t Ama, Ame, Ami, Amo, Amu;
        uint64_t Asa, Ase, Asi, Aso, Asu;
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        Aba = state[ 0];
        Abe = state[ 1];
        Abi = state[ 2];
        Abo = state[ 3];
        Abu = state[ 4];
        Aga = state[ 5];
        Age = state[ 6];
        Agi = state[ 7];
        Ago = state[ 8];
        Agu = state[ 9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for( round = 0; round < NROUNDS; round += 2 )
        {
            //    prepareTheta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= (uint64_t)KeccakF_RoundConstants[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka,  3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = ROL(Abe,  1);
            Agi ^= Di;
            BCe = ROL(Agi,  6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL(Amu,  8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^ROL(BCe, 1);
            De = BCa^ROL(BCi, 1);
            Di = BCe^ROL(BCo, 1);
            Do = BCi^ROL(BCu, 1);
            Du = BCo^ROL(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= (uint64_t)KeccakF_RoundConstants[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        state[ 0] = Aba;
        state[ 1] = Abe;
        state[ 2] = Abi;
        state[ 3] = Abo;
        state[ 4] = Abu;
        state[ 5] = Aga;
        state[ 6] = Age;
        state[ 7] = Agi;
        state[ 8] = Ago;
        state[ 9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;
}


void hash_init(unsigned char*state)
{
    memset(state,0,200);
}

void hash_absorb(unsigned char* state, uint32_t *in, size_t len)
{
    shake128_absorb((uint64_t*)state,(uint32_t*) in,len/sizeof(uint32_t));
}

void hash_gen(uint32_t* output, unsigned char *state)
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

void H(uint32_t* c, uint32_t* rho, uint32_t* t1, uint32_t* w1)
{
    unsigned char state[200];
    hash_init(state);
    hash_absorb(state, (uint32_t *)rho,8);
    hash_absorb(state, t1,t__len);
    hash_absorb(state, w1, w__len);
    hash_gen(c,state);
}



