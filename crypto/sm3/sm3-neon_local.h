# ifndef OPENSSL_NO_SM3_NEON

#include <arm_neon.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto/sm3-neon.h"
//#include "NEON_2_SSE.h"

uint32_t ll_neon_bswap4(uint32_t a) {
    uint32x2_t tmp = vdup_n_u32(a); 
    uint8x8_t reversed = vrev32_u8(vreinterpret_u8_u32(tmp)); 
    return vget_lane_u32(vreinterpret_u32_u8(reversed), 0); 
}

uint64_t ll_neon_bswap8(uint64_t a) {
    uint64x1_t tmp = vdup_n_u64(a); 
    uint8x8_t reversed = vrev64_u8(vreinterpret_u8_u64(tmp)); 
    return vget_lane_u64(vreinterpret_u64_u8(reversed), 0); 
}

static const uint32_t Tj[] = {
    0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
    0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
    0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
    0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
    0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
    0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
    0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
    0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53,
    0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
    0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4,
    0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
    0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
    0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
    0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5
};

uint32_t rotate_neon_right(uint32_t n, int shift) {
    return (n >> shift) | (n << (32 - shift));
}

// void Print(uint32_t A, uint32_t B, uint32_t C, uint32_t D,uint32_t E, uint32_t F, uint32_t G, uint32_t H){
//     printf("%08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x\n", A,B,C,D,E,F,G,H);
// }

// void print_uint32x4(uint32x4_t v) { 
//     uint32_t W0 = vgetq_lane_u32(v, 0);  
//     uint32_t W1 = vgetq_lane_u32(v, 1);
//     uint32_t W2 = vgetq_lane_u32(v, 2);
//     uint32_t W3 = vgetq_lane_u32(v, 3);
//     printf("[ %08x, %08x, %08x, %08x ]\n", W0, W1, W2, W3); 
// }

void circular_shift_neon(uint32x4_t *M0, uint32x4_t *M1, uint32x4_t *M2, uint32x4_t *M3) {
    uint32x4_t first_element = *M0;  
        *M0 = *M1;  
        *M1 = *M2;
        *M2 = *M3;
        *M3 = first_element; 
}

void NEON_FIRST_16_ROUNDS_AND_SCHED_1(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{
    *XFER = veorq_u32(*X0, *X1);                                // WW
    uint32_t t0 = rotate_neon_right(*A, 20);                         // A <<< 12
    *XTMP0 = vextq_u32(*X0, *X1, 3);                            // (W[-13],W[-12],W[-11],XXX)
    uint32_t t1 = *A ^ *B;                                      // A ^ B
    uint32_t t3 = Tj[*j];   
    *j +=1;          
    uint32_t t2 = t0 + *E;                                      // (A <<< 12) + E
    *XTMP1 = vshlq_n_u32(*XTMP0, 7);
    uint32_t W = vgetq_lane_u32(*X0, 0);                        // W[-16]
    uint32_t t5 = *E ^ *F;                                      // E ^ F
    t1 = t1 ^ *C;                                               // FF(A, B, C)
    uint32_t t4 = t2 + t3;                                      // (A <<< 12) + E + (Tj <<< j)
    *XTMP2 = vshrq_n_u32(*XTMP0, 25);
    t5 = t5 ^ *G;                                               // GG(E, F, G)
    *H = *H + W;                                                // H + Wj
    t4 = rotate_neon_right(t4, 25);                                  // SS1
    *XTMP0 = veorq_u32(*XTMP1, *XTMP2);                         // (W[-13],W[-12],W[-11],XXX) <<< 7
    *D = *D + t1;                                               // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                  // B <<< 9
    t1 = t4 + t5;                                               // GG(E, F, G) + SS1
    *XTMP2 = vextq_u32(*X2, *X3, 2);                            // (W[-6],W[-5],W[-4],XXX)
    W = vgetq_lane_u32(*XFER, 0);                               // WW[-16]
    t2 = t0 ^ t4;                                               // SS2
    *H = *H + t1;                                               // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                  // F <<< 19
    *XTMP0 = veorq_u32(*XTMP0, *XTMP2);                         // (W[-6],W[-5],W[-4],XXX)^((W[-13],W[-12],W[-11],XXX) <<< 17)
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                               // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);                             // P0(TT2)
    *XTMP1 = vextq_u32(*X3, *X2, 1);                            // (W[-3],W[-2],W[-1],XXX)
    *D = *D + W;                                                // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                               // Final P0(TT2)
}

void NEON_FIRST_16_ROUNDS_AND_SCHED_2(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{
    uint32_t t0 = rotate_neon_right(*A, 20);                         // A <<< 12 
    *XTMP2 = vshlq_n_u32(*XTMP1, 15);
    uint32_t t1 = *A ^ *B;                                      // A ^ B
    uint32_t t3 = Tj[*j];                                       // Tj <<< j
    *j +=1;
    uint32_t t2 = t0 + *E;                                      // (A <<< 12) + E
    *XTMP1 = vshrq_n_u32(*XTMP1, 17);
    uint32_t W = vgetq_lane_u32(*X0, 1);                        // W[-15]
    uint32_t t5 = *E ^ *F;                                      // E ^ F
    t1 = t1 ^ *C;                                               // FF(A, B, C)
    uint32_t t4 = t2 + t3;                                      // (A <<< 12) + E + (Tj <<< j)
    *XTMP1 = veorq_u32(*XTMP1, *XTMP2);                         // (W[-3],W[-2],W[-1],XXX) <<< 15
    t5 = t5 ^ *G;                                               // GG(E, F, G)
    *H = *H + W;                                                // H + Wj
    t4 = rotate_neon_right(t4, 25);                                  // SS1
    *XTMP2 = vextq_u32(*X1, *X2, 3);                            // W[-9],W[-8],W[-7],W[-6]
    *D = *D + t1;                                               // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                  // B <<< 9
    t1 = t4 + t5;                                               // GG(E, F, G) + SS1
    *XTMP2 = veorq_u32(*XTMP2, *X0);                            // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
    W = vgetq_lane_u32(*XFER, 1);                               // WW[-15]
    t2 = t0 ^ t4;                                               // SS2
    *H = *H + t1;                                               // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                  // F <<< 19
    *XTMP1 = veorq_u32(*XTMP1, *XTMP2);                         
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                               // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);                             // P0(TT2)
    *XTMP3 = vshlq_n_u32(*XTMP1, 15);                           // P1(X), X << 15
    *D = *D + W;                                                // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                               // P0(TT2)
}

void NEON_FIRST_16_ROUNDS_AND_SCHED_3(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{
    uint32_t t0 = rotate_neon_right(*A, 20);                         // A <<< 12 
    *XTMP4 = vshrq_n_u32(*XTMP1, 17);
    uint32_t t1 = *A ^ *B;                                      // A ^ B
    uint32_t t3 = Tj[*j];                                       // Tj <<< j
    *j +=1;
    uint32_t t2 = t0 + *E;                                      // (A <<< 12) + E
    *XTMP3 = veorq_u32(*XTMP3, *XTMP4);
    uint32_t W = vgetq_lane_u32(*X0, 2);                        // W[-14]
    uint32_t t5 = *E ^ *F;                                      // E ^ F
    t1 = t1 ^ *C;                                               // FF(A, B, C)
    uint32_t t4 = t2 + t3;                                      // (A <<< 12) + E + (Tj <<< j)
    *XTMP4 = vshlq_n_u32(*XTMP1, 23);
    t5 = t5 ^ *G;                                               // GG(E, F, G)
    *H = *H + W;                                                // H + Wj
    t4 = rotate_neon_right(t4, 25);                                  // SS1
    *XTMP5 = vshrq_n_u32(*XTMP1, 9);
    *D = *D + t1;                                               // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                  // B <<< 9
    t1 = t4 + t5;                                               // GG(E, F, G) + SS1
    *XTMP5 = veorq_u32(*XTMP4, *XTMP5);                         // P1(X), X << 23 ^ X >> 9
    W = vgetq_lane_u32(*XFER, 2);                               // WW[-14]
    t2 = t0 ^ t4;                                               // SS2
    *H = *H + t1;                                               // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                  // F <<< 19
    *XTMP1 = veorq_u32(*XTMP1, *XTMP3);                         // P1(X), X ^ (X <<< 15)
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                               // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);                             // P0(TT2)
    *XTMP1 = veorq_u32(*XTMP1, *XTMP5);                         // P1(X), X ^ (X <<< 15) ^ (X <<< 23)
    *D = *D + W;                                                // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                               // P0(TT2)
}

void NEON_FIRST_16_ROUNDS_AND_SCHED_4(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{

    uint32_t W = vgetq_lane_u32(*X0, 3);                         // W[-13]
    uint32_t t0 = rotate_neon_right(*A, 20);                          // A <<< 12
    *X0 = veorq_u32(*XTMP1, *XTMP0);                             // W[0], W[1], W[2], XXX
    uint32_t t1 = *A ^ *B;                                       // A ^ B
    uint32_t t3 = Tj[*j];                                        // Tj <<< j
    *j +=1;
    uint32_t t2 = t0 + *E;                                       // (A <<< 12) + E
    uint32_t T0 = vgetq_lane_u32(*X0, 0);                        // W[0]
    uint32_t t5 = *E ^ *F;                                       // E ^ F
    t1 = t1 ^ *C;                                                // FF(A, B, C)
    uint32_t T1 = vgetq_lane_u32(*XTMP2, 3);                     // W[-13] ^ W[-6]
    uint32_t t4 = t2 + t3;                                       // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 ^ *G;                                                // GG(E, F, G)
    uint32_t T2 = vgetq_lane_u32(*XTMP0, 3);                     // (W[-10] <<< 7) ^ W[-3]
    T0 = rotate_neon_right(T0,17);
    T1 = T1 ^ T0;                                                // Z = W[-13] ^ W[-6] ^ (W[0] <<< 15)
    *H = *H + W;                                                 // H + Wj
    t4 = rotate_neon_right(t4, 25);                                   // SS1
    *D = *D + t1;                                                // FF(A, B, C) + D
    uint32_t T3 = rotate_neon_right(T1, 17);                          // Z <<< 15
    *B = rotate_neon_right(*B, 23);                                   // B <<< 9
    t1 = t4 + t5;                                                // GG(E, F, G) + SS1
    T1 = T1 ^ rotate_neon_right(T1, 9);                               // Z ^ (Z <<< 23)
    W = vgetq_lane_u32(*XFER, 3);                                // WW[-13]
    t2 = t0 ^ t4;                                                // SS2
    *H = *H + t1;                                                // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                   // F <<< 19
    T1 = T1 ^ T3;                                                // Z ^ (Z <<< 15) ^ (Z <<< 23)
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                               // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);                             // P0(TT2)
    T2 = T1 ^ T2;                                               // W[3]
    *D = *D + W;                                                // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                               // P0(TT2)
    *X0 = vsetq_lane_u32(T2, *X0, 3);                           // W[0], W[1], W[2], W[3]
}

void NEON_SECOND_36_ROUNDS_AND_SCHED_1(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;
    *XFER = veorq_u32(*X0, *X1);                                 // WW
    t0 = rotate_neon_right(*A, 20);                                   // A <<< 12
    *XTMP0 = vextq_u32(*X0, *X1, 3);                             // (W[-13],W[-12],W[-11],XXX)
    t1 = *B | *C;                                                // B | C
    t3 = Tj[*j];                                                 // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                                // (A <<< 12) + E
    T0 = *B & *C;                                                // B & C
    *XTMP1 = vshlq_n_u32(*XTMP0, 7);                             // ((W[-13],W[-12],W[-11],XXX) << 7)
    T1 = *A & t1;                                                // A & (B | C)
    W = vgetq_lane_u32(*X0, 0);                                  // W[-16]
    t5 = *F ^ *G;                                                // F ^ G
    t1 = T0 | T1;                                                // FF(A, B, C)
    t4 = t2 + t3;                                                // (A <<< 12) + E + (Tj <<< j)
    *XTMP2 = vshrq_n_u32(*XTMP0, 25);                            // (W[-13],W[-12],W[-11],XXX) >> 25
    t5 = t5 & *E;                                                // (F ^ G) & E
    *H = *H + W;                                                 // H + Wj
    t4 = rotate_neon_right(t4, 25);                                   // SS1
    *XTMP0 = veorq_u32(*XTMP1, *XTMP2);                          // (W[-13],W[-12],W[-11],XXX] <<< 17
    t5 = t5 ^ *G;                                                // GG(E, F, G)
    *D = *D + t1;                                                // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                   // B <<< 9
    *XTMP2 = vextq_u32(*X2, *X3, 2);                             // (W[-6],W[-5],W[-4],XXX)
    t1 = t4 + t5;                                                // GG(E, F, G) + SS1
    W = vgetq_lane_u32(*XFER, 0);                                // WW[-16]
    t2 = t0 ^ t4;                                                // SS2
    *H = *H + t1;                                                // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                   // F <<< 19
    *XTMP0 = veorq_u32(*XTMP0, *XTMP2);                          // (W[-6],W[-5],W[-4],XXX)^((W[-13],W[-12],W[-11],XXX) <<< 17)
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    *XTMP1 = vextq_u32(*X3, *X2, 1);                             // (W[-3],W[-2],W[-1],XXX)
    *D = *D + W;                                                 // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                // P0(TT2)
}

void NEON_SECOND_36_ROUNDS_AND_SCHED_2(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;
    t0 = rotate_neon_right(*A, 20);                                    // A <<< 12
    *XTMP2 = vshlq_n_u32(*XTMP1, 15);                             // (W[-3],W[-2],W[-1],XXX) << 15
    t1 = *B | *C;                                                 // B | C
    t3 = Tj[*j];                                                  // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                                 // (A <<< 12) + E
    T0 = *B & *C;                                                 // B & C
    *XTMP1 = vshrq_n_u32(*XTMP1, 17);                             // (W[-3],W[-2],W[-1],XXX) >> 17
    T1 = *A & t1;                                                 // A & (B | C)
    W = vgetq_lane_u32(*X0, 1);                                   // W[-15]
    t5 = *F ^ *G;                                                 // F ^ G
    t1 = T0 | T1;                                                 // FF(A, B, C)
    t4 = t2 + t3;                                                 // (A <<< 12) + E + (Tj <<< j)
    *XTMP1 = veorq_u32(*XTMP2, *XTMP1);                           // (W[-3],W[-2],W[-1],XXX) <<< 15
    t5 = t5 & *E;                                                 // (F ^ G) & E
    *H = *H + W;                                                  // H + Wj
    t4 = rotate_neon_right(t4, 25);                                    // SS1
    *XTMP2 = vextq_u32(*X1, *X2, 3);                              // W[-9],W[-8],W[-7],W[-6]
    t5 = t5 ^ *G;                                                 // GG(E, F, G)
    *D = *D + t1;                                                 // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                    // B <<< 9
    *XTMP2 = veorq_u32(*XTMP2, *X0);                              // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
    t1 = t4 + t5;                                                 // GG(E, F, G) + SS1
    W = vgetq_lane_u32(*XFER, 1);                                 // WW[-15]
    t2 = t0 ^ t4;                                                 // SS2
    *H = *H + t1;                                                 // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                    // F <<< 19
    *XTMP1 = veorq_u32(*XTMP1, *XTMP2);                
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                 // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    *XTMP3 = vshlq_n_u32(*XTMP1, 15);                             // P1(X), X << 15
    *D = *D + W;                                                  // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                 // P0(TT2)
}

void NEON_SECOND_36_ROUNDS_AND_SCHED_3(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;
    t0 = rotate_neon_right(*A, 20);                                    // A <<< 12
    *XTMP4 = vshrq_n_u32(*XTMP1, 17);                             // P1(X), X >> 17
    t1 = *B | *C;                                                 // B | C
    t3 = Tj[*j];                                                  // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                                 // (A <<< 12) + E
    T0 = *B & *C;                                                 // B & C
    *XTMP3 = veorq_u32(*XTMP3, *XTMP4);                           // P1(X), X <<< 15
    T1 = *A & t1;                                                 // A & (B | C)
    W = vgetq_lane_u32(*X0, 2);                                   // W[-14]
    t5 = *F ^ *G;                                                 // F ^ G
    t1 = T0 | T1;                                                 // FF(A, B, C)
    t4 = t2 + t3;                                                 // (A <<< 12) + E + (Tj <<< j)
    *XTMP4 = vshlq_n_u32(*XTMP1, 23);                             // P1(X), X << 23
    t5 = t5 & *E;                                                 // (F ^ G) & E
    *H = *H + W;                                                  // H + Wj
    t4 = rotate_neon_right(t4, 25);                                    // SS1
    *XTMP5 = vshrq_n_u32(*XTMP1, 9);                              // P1(X), X >> 9
    t5 = t5 ^ *G;                                                 // GG(E, F, G)
    *D = *D + t1;                                                 // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                    // B <<< 9
    *XTMP5 = veorq_u32(*XTMP4, *XTMP5);                           // P1(X), X << 23
    t1 = t4 + t5;                                                 // GG(E, F, G) + SS1
    W = vgetq_lane_u32(*XFER, 2);                                 // WW[-14]
    t2 = t0 ^ t4;                                                 // SS2
    *H = *H + t1;                                                 // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                    // F <<< 19
    *XTMP1 = veorq_u32(*XTMP1, *XTMP3);                           // P1(X), X ^ (X <<< 15)
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                 // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    *XTMP1 = veorq_u32(*XTMP1, *XTMP5);                           // P1(X), X ^ (X <<< 15) ^ (X <<< 23)
    *D = *D + W;                                                  // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                 // P0(TT2)
}

void NEON_SECOND_36_ROUNDS_AND_SCHED_4(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, uint32x4_t *XTMP0, uint32x4_t *XTMP1,uint32x4_t *XTMP2, uint32x4_t *XTMP3, uint32x4_t *XTMP4, uint32x4_t *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, T2, T3, T4, W;
    W = vgetq_lane_u32(*X0, 3);                                   // W[-13]
    t0 = rotate_neon_right(*A, 20);                                    // A <<< 12
    *X0 = veorq_u32(*XTMP1, *XTMP0);                              // W[0],W[1],W[2],XXX
    t1 = *B | *C;                                                 // B | C
    t3 = Tj[*j];                                                  // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                                 // (A <<< 12) + E
    T0 = vgetq_lane_u32(*X0, 0);                                  // W[0]
    T3 = *B & *C;                                                 // B & C
    T4 = *A & t1;                                                 // A & (B | C)
    T1 = vgetq_lane_u32(*XTMP2, 3);                               // W[-13] ^ W[-6]
    t5 = *F ^ *G;                                                 // F ^ G
    t1 = T3 | T4;                                                 // FF(A, B, C)
    T2 = vgetq_lane_u32(*XTMP0, 3);                               // (W[-10] <<< 7) ^ W[-3]
    T1 = rotate_neon_right(T0, 17) ^ T1;                               // Z = W[-13] ^ W[-6] ^ (W[0] <<< 15)
    t4 = t2 + t3;                                                 // (A <<< 12) + E + (Tj <<< j)
    T3 = rotate_neon_right(T1, 17);                                    // Z <<< 15
    t5 = t5 & *E;                                                 // (F ^ G) & E
    *H = *H + W;                                                  // H + Wj
    t4 = rotate_neon_right(t4, 25);                                    // SS1
    T1 = T1 ^ rotate_neon_right(T1, 9);                                // Z ^ (Z <<< 23)
    t5 = t5 ^ *G;                                                 // GG(E, F, G)
    *D = *D + t1;                                                 // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                    // B <<< 9
    W = vgetq_lane_u32(*XFER, 3);                                 // WW[-13]
    t1 = t4 + t5;                                                 // GG(E, F, G) + SS1
    t2= t0 ^ t4;                                                  // SS2
    *H = *H + t1;                                                 // TT2 = GG(E, F, G) + H + SS1 + Wj
    T1 = T1 ^ T3;                                                 // Z ^ (Z <<< 15) ^ (Z <<< 23)
    *F = rotate_neon_right(*F, 13);                                    // F <<< 19
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                 // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    T2 = T1 ^ T2;                                                 // W[3]
    *D = *D + W;                                                  // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                 // P0(TT2)
    *X0=vsetq_lane_u32(T2, *X0, 3);                               // W[0],W[1],W[2],W[3]
}

void NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_1(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
uint32x4_t *XFER, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, W, T0, T1;
    *XFER = veorq_u32(*X0, *X1);                                  // WW
    t0 = rotate_neon_right(*A, 20);                                    // A <<< 12
    t1 = *B | *C;                                                 // B | C
    T0 = *B & *C;                                                 // B & C
    T1 = *A & t1;                                                 // A & (B | C)
    W = vgetq_lane_u32(*X0, 0);                                   // W[-16]
    t3 = Tj[*j];                                                  // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                                 // (A <<< 12) + E
    t5 = *F ^ *G;                                                 // F ^ G
    t1 = T0 | T1;                                                 // FF(A, B, C)
    t4 = t2 + t3;                                                 // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                                 // (F ^ G) & E
    *H = *H + W;                                                  // H + Wj
    t4 = rotate_neon_right(t4, 25);                                    // SS1
    t5 = t5 ^ *G;                                                 // GG(E, F, G)
    *D = *D + t1;                                                 // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                    // B <<< 9
    t1 = t4 + t5;                                                 // GG(E, F, G) + SS1
    W = vgetq_lane_u32(*XFER, 0);                                 // WW[-16]
    t2 = t0 ^ t4;                                                 // SS2
    *H = *H + t1;                                                 // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                    // F <<< 19
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                 // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    *D = *D + W;                                                  // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                 // P0(TT2)
}

void NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_2(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,uint32x4_t *XFER, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, W, T0, T1;
    t0 = rotate_neon_right(*A, 20);                                    // A <<< 12
    t1 = *B | *C;                                                 // B | C
    T0 = *B & *C;                                                 // B & C
    T1 = *A & t1;                                                 // A & (B | C)
    W = vgetq_lane_u32(*X0, 1); 
    t3 = Tj[*j];                                                  // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                                 // (A <<< 12) + E
    t5 = *F ^ *G;                                                 // F ^ G
    t1 = T0 | T1;                                                 // FF(A, B, C)
    t4 = t2 + t3;                                                 // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                                 // (F ^ G) & E
    *H = *H + W;                                                  // H + Wj
    t4 = rotate_neon_right(t4, 25);                                    // SS1
    t5 = t5 ^ *G;                                                 // GG(E, F, G)
    *D = *D + t1;                                                 // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                    // B <<< 9
    t1 = t4 + t5;                                                 // GG(E, F, G) + SS1
    W = vgetq_lane_u32(*XFER, 1); 
    t2 = t0 ^ t4;                                                 // SS2
    *H = *H + t1;                                                 // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                    // F <<< 19
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                 // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    *D = *D + W;                                                  // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                 // P0(TT2)
}

void NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_3(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3,
                                     uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,uint32x4_t *XFER, int *j) {
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;

    t0 = rotate_neon_right(*A, 20);                                    // A <<< 12
    t1 = *B | *C;                                                 // B | C
    t3 = Tj[*j];
    *j +=1;
    t2 = t0 + *E;                                                 // (A <<< 12) + E
    T0 = *B & *C;                                                 // B & C
    T1 = *A & t1;                                                 // A & (B | C)
    W = vgetq_lane_u32(*X0, 2);
    t5 = *F ^ *G;                                                 // F ^ G
    t1 = T0 | T1;                                                 // FF(A, B, C)
    t4 = t2 + t3;                                                 // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                                 // (F ^ G) & E
    *H = *H + W;                                                  // H + Wj
    t4 = rotate_neon_right(t4, 25);                                    // SS1
    t5 = t5 ^ *G;                                                 // GG(E, F, G)
    *D = t1 + *D;                                                 // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                    // B <<< 9
    t1 = t4 + t5;                                                 // GG(E, F, G) + SS1
    W = vgetq_lane_u32(*XFER, 2); 
    t2 = t0 ^ t4;                                                 // SS2
    *H = *H + t1;                                                 // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                    // F <<< 19
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                 // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    *D = *D + W;                                                  // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                 // P0(TT2)
}

void NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_4(uint32x4_t *X0, uint32x4_t *X1, uint32x4_t *X2, uint32x4_t *X3,
                                          uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,uint32x4_t *XFER, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5;
    uint32_t T0, T1, W, WW;
    t0 = rotate_neon_right(*A, 20);                                    // A <<< 12
    t1 = *B | *C;                                                 // B | C
    t3 = Tj[*j];                                                  // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                                 // (A <<< 12) + E
    T0 = *B & *C;                                                 // B & C
    T1 = *A & t1;                                                 // A & (B | C)
    W = vgetq_lane_u32(*X0, 3);                                   // W[-16]
    t5 = *F ^ *G;                                                 // F ^ G
    t1 = T0 | T1;                                                 // FF(A, B, C)
    t4 = t2 + t3;                                                 // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                                 // (F ^ G) & E
    *H = *H + W;                                                  // H + Wj
    t4 = rotate_neon_right(t4, 25);                                    // SS1
    t5 = t5 ^ *G;                                                 // GG(E, F, G)
    *D = t1 + *D;                                                 // FF(A, B, C) + D
    *B = rotate_neon_right(*B, 23);                                    // B <<< 9
    t1 = t4 + t5;                                                 // GG(E, F, G) + SS1
    W = vgetq_lane_u32(*XFER, 3);                                 // WW[-16]
    t2 = t0 ^ t4;                                                 // SS2
    *H = *H + t1;                                                 // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_neon_right(*F, 13);                                    // F <<< 19
    t3 = rotate_neon_right(*H, 23);
    *D = *D + t2;                                                 // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_neon_right(*H, 15);
    *D = *D + W;                                                  // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                                 // P0(TT2)
}

void sm3_compress_neon(uint32_t digest[8], const uint8_t *buf, uint64_t nb) {
    u32 a,b,c,d,e,f,g,h;
    uint32_t A,B,C,D,E,F,G,H;
    uint32x4_t low = vld1q_u32(digest);
    uint32x4_t high = vld1q_u32(digest + 4);
    
    a = vgetq_lane_u32(low, 0);     
    b = vgetq_lane_u32(low, 1);
    c = vgetq_lane_u32(low, 2);
    d = vgetq_lane_u32(low, 3);
    e = vgetq_lane_u32(high, 0);
    f = vgetq_lane_u32(high, 1);
    g = vgetq_lane_u32(high, 2);
    h = vgetq_lane_u32(high, 3);
    A = a;
    B = b;
    C = c;
    D = d;
    E = e;
    F = f;
    G = g;
    H = h;

    while (nb--) {
        uint8x16_t M0 = vld1q_u8(buf);
        uint8x16_t M1 = vld1q_u8(buf + 16);
        uint8x16_t M2 = vld1q_u8(buf + 32);
        uint8x16_t M3 = vld1q_u8(buf + 48);
        buf += 64;                                 //for next turn

        int i = 1;
        char test = (*(char*)&i);
        if (test){
        M0 = vrev32q_u8(M0);
        M1 = vrev32q_u8(M1);
        M2 = vrev32q_u8(M2);
        M3 = vrev32q_u8(M3);
        }
        int j=0;

        uint32x4_t X0=vreinterpretq_u32_u8(M0);
        uint32x4_t X1=vreinterpretq_u32_u8(M1);
        uint32x4_t X2=vreinterpretq_u32_u8(M2);
        uint32x4_t X3=vreinterpretq_u32_u8(M3);
        
        uint32x4_t XFER; uint32x4_t XTMP0; uint32x4_t XTMP1;uint32x4_t XTMP2; uint32x4_t XTMP3; uint32x4_t XTMP4; uint32x4_t XTMP5;
        for (int i = 0; i < 4; i++) {
            NEON_FIRST_16_ROUNDS_AND_SCHED_1(&X0, &X1, &X2, &X3, &A, &B, &C, &D, &E, &F, &G, &H, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            NEON_FIRST_16_ROUNDS_AND_SCHED_2(&X0, &X1, &X2, &X3, &D, &A, &B, &C, &H, &E, &F, &G, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            NEON_FIRST_16_ROUNDS_AND_SCHED_3(&X0, &X1, &X2, &X3, &C, &D, &A, &B, &G, &H, &E, &F, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            NEON_FIRST_16_ROUNDS_AND_SCHED_4(&X0, &X1, &X2, &X3, &B, &C, &D, &A, &F, &G, &H, &E, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            circular_shift_neon(&X0, &X1, &X2, &X3);
        }

        for (int i = 0; i < 9; i++) {
            NEON_SECOND_36_ROUNDS_AND_SCHED_1(&X0, &X1, &X2, &X3, &A, &B, &C, &D, &E, &F, &G, &H, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            NEON_SECOND_36_ROUNDS_AND_SCHED_2(&X0, &X1, &X2, &X3, &D, &A, &B, &C, &H, &E, &F, &G, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            NEON_SECOND_36_ROUNDS_AND_SCHED_3(&X0, &X1, &X2, &X3, &C, &D, &A, &B, &G, &H, &E, &F, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            NEON_SECOND_36_ROUNDS_AND_SCHED_4(&X0, &X1, &X2, &X3, &B, &C, &D, &A, &F, &G, &H, &E, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            circular_shift_neon(&X0, &X1, &X2, &X3);
        }

        for (int i = 0; i < 3; i++) {
            NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_1(&X0, &X1, &X2, &X3, &A, &B, &C, &D, &E, &F, &G, &H, &XFER,&j);
            NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_2(&X0, &X1, &X2, &X3, &D, &A, &B, &C, &H, &E, &F, &G, &XFER,&j);
            NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_3(&X0, &X1, &X2, &X3, &C, &D, &A, &B, &G, &H, &E, &F, &XFER,&j);
            NEON_THIRD_12_ROUNDS_WITHOUT_SCHED_4(&X0, &X1, &X2, &X3, &B, &C, &D, &A, &F, &G, &H, &E, &XFER,&j);
            circular_shift_neon(&X0, &X1, &X2, &X3);
        }
            a = a ^ A;
            b = b ^ B;
            c = c ^ C;
            d = d ^ D;
            e = e ^ E;
            f = f ^ F;
            g = g ^ G;
            h = h ^ H;
            A=a;
            B=b;
            C=c;
            D=d;
            E=e;
            F=f;
            G=g;
            H=h;
    }
    digest[0]=a;
    digest[1]=b;
    digest[2]=c;
    digest[3]=d;
    digest[4]=e;
    digest[5]=f;
    digest[6]=g;
    digest[7]=h;
}

#endif