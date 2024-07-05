#ifndef OPENSSL_NO_SM3_AVX
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto/sm3-avx.h"
#include <immintrin.h>

uint32_t ll_avx_bswap4(uint32_t a) {
    uint32_t tmp = ((a & 0x000000ff)<<24)|((a & 0x0000ff00)<<8)|((a & 0x00ff0000)>>8)|((a & 0xff000000)>>24);
    return tmp;
}

uint64_t ll_avx_bswap8(uint64_t a) {
    uint64_t tmp = ((a & 0x00000000000000ff)<<56)|((a & 0x000000000000ff00)<<40)|((a & 0x0000000000ff0000)<<24)|((a & 0x00000000ff000000)<<8)|\
    ((a & 0xff00000000000000)>>56)|((a & 0x00ff000000000000)>>40)|((a & 0x0000ff0000000000)>>24)|((a & 0x000000ff00000000)>>8);
    return tmp;
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

void Print(uint32_t A, uint32_t B, uint32_t C, uint32_t D,uint32_t E, uint32_t F, uint32_t G, uint32_t H){
    printf("%08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x\n", A,B,C,D,E,F,G,H);
}

void print_m256i(__m256i v) { 
    uint32_t W0 = _mm256_extract_epi32(v, 3);  // 将向量中的值存储到数组中 
    uint32_t W1 = _mm256_extract_epi32(v, 2);
    uint32_t W2 = _mm256_extract_epi32(v, 1);
    uint32_t W3 = _mm256_extract_epi32(v, 0);
    printf("[ %08x, %08x, %08x, %08x ]\n", W0, W1, W2, W3); // 打印数组中的值 
}

__m256i _mm256_ext_si256_1(__m256i X0, __m256i X1){
    uint32_t a1,b1,c1,d1;
    __m256i tmp;
    //printf("test1\n");
    a1 = _mm256_extract_epi32(X0,2);
    b1 = _mm256_extract_epi32(X0,1);
    c1 = _mm256_extract_epi32(X0,0);
    d1 = _mm256_extract_epi32(X1,3);
    tmp = _mm256_set_epi32(a1,b1,c1,d1,a1,b1,c1,d1);
    return tmp;
}

__m256i _mm256_ext_si256_2(__m256i X0, __m256i X1){
    uint32_t a1,b1,c1,d1;
    __m256i tmp;
    //printf("test2\n");
    a1 = _mm256_extract_epi32(X0,1);
    b1 = _mm256_extract_epi32(X0,0);
    c1 = _mm256_extract_epi32(X1,3);
    d1 = _mm256_extract_epi32(X1,2);
    tmp = _mm256_set_epi32(a1,b1,c1,d1,a1,b1,c1,d1);
    return tmp;
}

__m256i _mm256_ext_si256_3(__m256i X0, __m256i X1){
    uint32_t a1,b1,c1,d1;
    __m256i tmp;
    //printf("test1\n");
    a1 = _mm256_extract_epi32(X0,0);
    b1 = _mm256_extract_epi32(X1,3);
    c1 = _mm256_extract_epi32(X1,2);
    d1 = _mm256_extract_epi32(X1,1);
    tmp = _mm256_set_epi32(a1,b1,c1,d1,a1,b1,c1,d1);
    return tmp;
}

// __m256i _mm256_ext_si256_3(__m256i X0, __m256i X1){
    
//     __m256i tmp;
//     uint32_t x;
//     __m256i indices = _mm256_setr_epi32(1, 2, 3, 0, 5, 6, 7, 4); 
//     __m256i result = _mm256_permutevar8x32_epi32(X1, indices);
//     x = _mm256_extract_epi32(X0 , 0);
//     tmp = _mm256_insert_epi32(result, x, 3);
//     tmp = _mm256_insert_epi32(tmp, x, 7);
//     return tmp;
// }

uint32_t rotate_avx_right(uint32_t n, int shift) {
    return (n >> shift) | (n << (32 - shift));
}

void circular_avx_shift(__m256i *M0, __m256i *M1, __m256i *M2, __m256i *M3) {
    __m256i first_element = *M0;  
        *M0 = *M1;  
        *M1 = *M2;
        *M2 = *M3;
        *M3 = first_element; 
}

void AVX_FIRST_16_ROUNDS_AND_SCHED_1(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    *XFER = _mm256_xor_si256(*X0, *X1);                   // WW
    uint32_t t0 = rotate_avx_right(*A, 20);                   // A <<< 12
    *XTMP0 = _mm256_ext_si256_3(*X0, *X1);                // (W[-13],W[-12],W[-11],XXX)
    uint32_t t1 = *A ^ *B;                                // A ^ B
    uint32_t t3 = Tj[*j];   
    *j +=1;          
    uint32_t t2 = t0 + *E;                                // (A <<< 12) + E
    *XTMP1 = _mm256_slli_epi32(*XTMP0, 7);
    uint32_t W = _mm256_extract_epi32(*X0, 3);            // W[-16]
    uint32_t t5 = *E ^ *F;                                // E ^ F
    t1 = t1 ^ *C;                                         // FF(A, B, C)
    uint32_t t4 = t2 + t3;                                // (A <<< 12) + E + (Tj <<< j)
    *XTMP2 = _mm256_srli_epi32(*XTMP0, 25);
    t5 = t5 ^ *G;                                         // GG(E, F, G)
    *H = *H + W;                                          // H + Wj
    t4 = rotate_avx_right(t4, 25);                            // SS1
    *XTMP0 = _mm256_xor_si256(*XTMP1, *XTMP2);            // (W[-13],W[-12],W[-11],XXX) <<< 7
    *D = *D + t1;                                         // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                            // B <<< 9
    t1 = t4 + t5;                                         // GG(E, F, G) + SS1
    *XTMP2 = _mm256_ext_si256_2(*X2, *X3);                // (W[-6],W[-5],W[-4],XXX)
    W = _mm256_extract_epi32(*XFER, 3);                   // WW[-16]
    t2 = t0 ^ t4;                                         // SS2
    *H = *H + t1;                                         // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                            // F <<< 19
    *XTMP0 = _mm256_xor_si256(*XTMP0, *XTMP2);            // (W[-6],W[-5],W[-4],XXX)^((W[-13],W[-12],W[-11],XXX) <<< 17)
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                         // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);                       // P0(TT2)
    *XTMP1 = _mm256_ext_si256_1(*X3, *X2);                // (W[-3],W[-2],W[-1],XXX)
    *D = *D + W;                                          // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                         // Final P0(TT2)

}

void AVX_FIRST_16_ROUNDS_AND_SCHED_2(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    uint32_t t0 = rotate_avx_right(*A, 20);                   // A <<< 12
    *XTMP2 = _mm256_slli_epi32(*XTMP1, 15);
    uint32_t t1 = *A ^ *B;                                // A ^ B
    uint32_t t3 = Tj[*j];                                 // Tj <<< j
    *j +=1;
    uint32_t t2 = t0 + *E;                                // (A <<< 12) + E
    *XTMP1 = _mm256_srli_epi32(*XTMP1, 17);
    uint32_t W = _mm256_extract_epi32(*X0, 2);            // W[-15]
    uint32_t t5 = *E ^ *F;                                // E ^ F
    t1 = t1 ^ *C;                                         // FF(A, B, C)
    uint32_t t4 = t2 + t3;                                // (A <<< 12) + E + (Tj <<< j)
    *XTMP1 = _mm256_xor_si256(*XTMP1, *XTMP2);            // (W[-3],W[-2],W[-1],XXX) <<< 15
    t5 = t5 ^ *G;                                         // GG(E, F, G)
    *H = *H + W;                                          // H + Wj
    t4 = rotate_avx_right(t4, 25);                            // SS1
    *XTMP2 = _mm256_ext_si256_3(*X1, *X2);                // W[-9],W[-8],W[-7],W[-6]
    *D = *D + t1;                                         // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                            // B <<< 9
    t1 = t4 + t5;                                         // GG(E, F, G) + SS1
    *XTMP2 = _mm256_xor_si256(*XTMP2, *X0);               // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
    W = _mm256_extract_epi32(*XFER, 2);                   // WW[-15]
    t2 = t0 ^ t4;                                         // SS2
    *H = *H + t1;                                         // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                            // F <<< 19
    *XTMP1 = _mm256_xor_si256(*XTMP1, *XTMP2);            
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                         // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);                       // P0(TT2)
    *XTMP3 = _mm256_slli_epi32(*XTMP1, 15);               // P1(X), X << 15
    *D = *D + W;                                          // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                         // P0(TT2)
}

void AVX_FIRST_16_ROUNDS_AND_SCHED_3(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    uint32_t t0 = rotate_avx_right(*A, 20);                   // A <<< 12
    *XTMP4 = _mm256_srli_epi32(*XTMP1, 17);
    uint32_t t1 = *A ^ *B;                                // A ^ B
    uint32_t t3 = Tj[*j];                                 // Tj <<< j
    *j +=1;
    uint32_t t2 = t0 + *E;                                // (A <<< 12) + E
    *XTMP3 = _mm256_xor_si256(*XTMP3, *XTMP4);
    uint32_t W = _mm256_extract_epi32(*X0, 1);            // W[-14]
    uint32_t t5 = *E ^ *F;                                // E ^ F
    t1 = t1 ^ *C;                                         // FF(A, B, C)
    uint32_t t4 = t2 + t3;                                // (A <<< 12) + E + (Tj <<< j)
    *XTMP4 = _mm256_slli_epi32(*XTMP1, 23);
    t5 = t5 ^ *G;                                         // GG(E, F, G)
    *H = *H + W;                                          // H + Wj
    t4 = rotate_avx_right(t4, 25);                            // SS1
    *XTMP5 = _mm256_srli_epi32(*XTMP1, 9);
    *D = *D + t1;                                         // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                            // B <<< 9
    t1 = t4 + t5;                                         // GG(E, F, G) + SS1
    *XTMP5 = _mm256_xor_si256(*XTMP4, *XTMP5);            // P1(X), X << 23 ^ X >> 9
    W = _mm256_extract_epi32(*XFER, 1);                   // WW[-14]
    t2 = t0 ^ t4;                                         // SS2
    *H = *H + t1;                                         // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                            // F <<< 19
    *XTMP1 = _mm256_xor_si256(*XTMP1, *XTMP3);            // P1(X), X ^ (X <<< 15)
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                         // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);                       // P0(TT2)
    *XTMP1 = _mm256_xor_si256(*XTMP1, *XTMP5);            // P1(X), X ^ (X <<< 15) ^ (X <<< 23)
    *D = *D + W;                                          // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                         // P0(TT2)
}

void AVX_FIRST_16_ROUNDS_AND_SCHED_4(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    uint32_t W = _mm256_extract_epi32(*X0, 0);            // W[-13]
    uint32_t t0 = rotate_avx_right(*A, 20);                   // A <<< 12
    *X0 = _mm256_xor_si256(*XTMP1, *XTMP0);               // W[0], W[1], W[2], XXX
    uint32_t t1 = *A ^ *B;                                // A ^ B
    uint32_t t3 = Tj[*j];                                 // Tj <<< j
    *j +=1;
    uint32_t t2 = t0 + *E;                                // (A <<< 12) + E
    uint32_t T0 = _mm256_extract_epi32(*X0, 3);           // W[0]
    uint32_t t5 = *E ^ *F;                                // E ^ F
    t1 = t1 ^ *C;                                         // FF(A, B, C)
    uint32_t T1 = _mm256_extract_epi32(*XTMP2, 0);        // W[-13] ^ W[-6]
    uint32_t t4 = t2 + t3;                                // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 ^ *G;                                         // GG(E, F, G)
    uint32_t T2 = _mm256_extract_epi32(*XTMP0, 0);        // (W[-10] <<< 7) ^ W[-3]
    T0 = rotate_avx_right(T0,17);
    T1 = T1 ^ T0;                                         // Z = W[-13] ^ W[-6] ^ (W[0] <<< 15)
    *H = *H + W;                                          // H + Wj
    t4 = rotate_avx_right(t4, 25);                            // SS1
    *D = *D + t1;                                         // FF(A, B, C) + D
    uint32_t T3 = rotate_avx_right(T1, 17);                   // Z <<< 15
    *B = rotate_avx_right(*B, 23);                            // B <<< 9
    t1 = t4 + t5;                                         // GG(E, F, G) + SS1
    T1 = T1 ^ rotate_avx_right(T1, 9);                        // Z ^ (Z <<< 23)
    W = _mm256_extract_epi32(*XFER, 0);                   // WW[-13]
    t2 = t0 ^ t4;                                         // SS2
    *H = *H + t1;                                         // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                            // F <<< 19
    T1 = T1 ^ T3;                                         // Z ^ (Z <<< 15) ^ (Z <<< 23)
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                         // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);                       // P0(TT2)
    T2 = T1 ^ T2;                                         // W[3]
    *D = *D + W;                                          // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                         // P0(TT2)
    *X0 = _mm256_insert_epi32(*X0,T2, 0);                 // W[0], W[1], W[2], W[3]
}

void AVX_SECOND_36_ROUNDS_AND_SCHED_1(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;
    *XFER = _mm256_xor_si256(*X0, *X1);                   // WW
    t0 = rotate_avx_right(*A, 20);                            // A <<< 12
    *XTMP0 = _mm256_ext_si256_3(*X0, *X1);                // (W[-13],W[-12],W[-11],XXX)
    t1 = *B | *C;                                         // B | C
    t3 = Tj[*j];                                          // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                         // (A <<< 12) + E
    T0 = *B & *C;                                         // B & C
    *XTMP1 = _mm256_slli_epi32(*XTMP0, 7);                // ((W[-13],W[-12],W[-11],XXX) << 7)
    T1 = *A & t1;                                         // A & (B | C)
    W = _mm256_extract_epi32(*X0, 3);                     // W[-16]
    t5 = *F ^ *G;                                         // F ^ G
    t1 = T0 | T1;                                         // FF(A, B, C)
    t4 = t2 + t3;                                         // (A <<< 12) + E + (Tj <<< j)
    *XTMP2 = _mm256_srli_epi32(*XTMP0, 25);               // (W[-13],W[-12],W[-11],XXX) >> 25
    t5 = t5 & *E;                                         // (F ^ G) & E
    *H = *H + W;                                          // H + Wj
    t4 = rotate_avx_right(t4, 25);                            // SS1
    *XTMP0 = _mm256_xor_si256(*XTMP1, *XTMP2);            // (W[-13],W[-12],W[-11],XXX] <<< 17
    t5 = t5 ^ *G;                                         // GG(E, F, G)
    *D = *D + t1;                                         // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                            // B <<< 9
    *XTMP2 = _mm256_ext_si256_2(*X2, *X3);                // (W[-6],W[-5],W[-4],XXX)
    t1 = t4 + t5;                                         // GG(E, F, G) + SS1
    W = _mm256_extract_epi32(*XFER, 3);                   // WW[-16]
    t2 = t0 ^ t4;                                         // SS2
    *H = *H + t1;                                         // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                            // F <<< 19
    *XTMP0 = _mm256_xor_si256(*XTMP0, *XTMP2);            // (W[-6],W[-5],W[-4],XXX)^((W[-13],W[-12],W[-11],XXX) <<< 17)
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                         // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    *XTMP1 = _mm256_ext_si256_1(*X3, *X2);                // (W[-3],W[-2],W[-1],XXX)
    *D = *D + W;                                          // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                         // P0(TT2)
}

void AVX_SECOND_36_ROUNDS_AND_SCHED_2(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;
    t0 = rotate_avx_right(*A, 20);                             // A <<< 12
    *XTMP2 = _mm256_slli_epi32(*XTMP1, 15);                // (W[-3],W[-2],W[-1],XXX) << 15
    t1 = *B | *C;                                          // B | C
    t3 = Tj[*j];                                           // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                          // (A <<< 12) + E
    T0 = *B & *C;                                          // B & C
    *XTMP1 = _mm256_srli_epi32(*XTMP1, 17);                // (W[-3],W[-2],W[-1],XXX) >> 17
    T1 = *A & t1;                                          // A & (B | C)
    W = _mm256_extract_epi32(*X0, 2);                      // W[-15]
    t5 = *F ^ *G;                                          // F ^ G
    t1 = T0 | T1;                                          // FF(A, B, C)
    t4 = t2 + t3;                                          // (A <<< 12) + E + (Tj <<< j)
    *XTMP1 = _mm256_xor_si256(*XTMP2, *XTMP1);             // (W[-3],W[-2],W[-1],XXX) <<< 15
    t5 = t5 & *E;                                          // (F ^ G) & E
    *H = *H + W;                                           // H + Wj
    t4 = rotate_avx_right(t4, 25);                             // SS1
    *XTMP2 = _mm256_ext_si256_3(*X1, *X2);                 // W[-9],W[-8],W[-7],W[-6]
    t5 = t5 ^ *G;                                          // GG(E, F, G)
    *D = *D + t1;                                          // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                             // B <<< 9
    *XTMP2 = _mm256_xor_si256(*XTMP2, *X0);                // (W[-9],W[-8],W[-7],W[-6]) ^ (W[-16],W[-15],W[-14],W[-13])
    t1 = t4 + t5;                                          // GG(E, F, G) + SS1
    W = _mm256_extract_epi32(*XFER, 2);                    // WW[-15]
    t2 = t0 ^ t4;                                          // SS2
    *H = *H + t1;                                          // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                             // F <<< 19
    *XTMP1 = _mm256_xor_si256(*XTMP1, *XTMP2);     
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                          // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    *XTMP3 = _mm256_slli_epi32(*XTMP1, 15);                // P1(X), X << 15
    *D = *D + W;                                           // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                          // P0(TT2)
}

void AVX_SECOND_36_ROUNDS_AND_SCHED_3(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;
    t0 = rotate_avx_right(*A, 20);                              // A <<< 12
    *XTMP4 = _mm256_srli_epi32(*XTMP1, 17);                 // P1(X), X >> 17
    t1 = *B | *C;                                           // B | C
    t3 = Tj[*j];                                            // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                           // (A <<< 12) + E
    T0 = *B & *C;                                           // B & C
    *XTMP3 = _mm256_xor_si256(*XTMP3, *XTMP4);              // P1(X), X <<< 15
    T1 = *A & t1;                                           // A & (B | C)
    W = _mm256_extract_epi32(*X0, 1);                       // W[-14]
    t5 = *F ^ *G;                                           // F ^ G
    t1 = T0 | T1;                                           // FF(A, B, C)
    t4 = t2 + t3;                                           // (A <<< 12) + E + (Tj <<< j)
    *XTMP4 = _mm256_slli_epi32(*XTMP1, 23);                 // P1(X), X << 23
    t5 = t5 & *E;                                           // (F ^ G) & E
    *H = *H + W;                                            // H + Wj
    t4 = rotate_avx_right(t4, 25);                              // SS1
    *XTMP5 = _mm256_srli_epi32(*XTMP1, 9);                  // P1(X), X >> 9
    t5 = t5 ^ *G;                                           // GG(E, F, G)
    *D = *D + t1;                                           // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                              // B <<< 9
    *XTMP5 = _mm256_xor_si256(*XTMP4, *XTMP5);              // P1(X), X << 23
    t1 = t4 + t5;                                           // GG(E, F, G) + SS1
    W = _mm256_extract_epi32(*XFER, 1);                     // WW[-14]
    t2 = t0 ^ t4;                                           // SS2
    *H = *H + t1;                                           // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                              // F <<< 19
    *XTMP1 = _mm256_xor_si256(*XTMP1, *XTMP3);              // P1(X), X ^ (X <<< 15)
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                           // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    *XTMP1 = _mm256_xor_si256(*XTMP1, *XTMP5);              // P1(X), X ^ (X <<< 15) ^ (X <<< 23)
    *D = *D + W;                                            // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                           // P0(TT2)
}

void AVX_SECOND_36_ROUNDS_AND_SCHED_4(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, __m256i *XTMP0, __m256i *XTMP1,__m256i *XTMP2, __m256i *XTMP3, __m256i *XTMP4, __m256i *XTMP5, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, T2, T3, T4, W;
    W = _mm256_extract_epi32(*X0, 0);                       // W[-13]
    t0 = rotate_avx_right(*A, 20);                              // A <<< 12
    *X0 = _mm256_xor_si256(*XTMP1, *XTMP0);                 // W[0],W[1],W[2],XXX
    t1 = *B | *C;                                           // B | C
    t3 = Tj[*j];                                            // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                           // (A <<< 12) + E
    T0 = _mm256_extract_epi32(*X0, 3);                      // W[0]
    T3 = *B & *C;                                           // B & C
    T4 = *A & t1;                                           // A & (B | C)
    T1 = _mm256_extract_epi32(*XTMP2, 0);                   // W[-13] ^ W[-6]
    t5 = *F ^ *G;                                           // F ^ G
    t1 = T3 | T4;                                           // FF(A, B, C)
    T2 = _mm256_extract_epi32(*XTMP0, 0);                   // (W[-10] <<< 7) ^ W[-3]
    T1 = rotate_avx_right(T0, 17) ^ T1;                         // Z = W[-13] ^ W[-6] ^ (W[0] <<< 15)
    t4 = t2 + t3;                                           // (A <<< 12) + E + (Tj <<< j)
    T3 = rotate_avx_right(T1, 17);                              // Z <<< 15
    t5 = t5 & *E;                                           // (F ^ G) & E
    *H = *H + W;                                            // H + Wj
    t4 = rotate_avx_right(t4, 25);                              // SS1
    T1 = T1 ^ rotate_avx_right(T1, 9);                          // Z ^ (Z <<< 23)
    t5 = t5 ^ *G;                                           // GG(E, F, G)
    *D = *D + t1;                                           // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                              // B <<< 9
    W = _mm256_extract_epi32(*XFER, 0);                     // WW[-13]
    t1 = t4 + t5;                                           // GG(E, F, G) + SS1
    t2= t0 ^ t4;                                            // SS2
    *H = *H + t1;                                           // TT2 = GG(E, F, G) + H + SS1 + Wj
    T1 = T1 ^ T3;                                           // Z ^ (Z <<< 15) ^ (Z <<< 23)
    *F = rotate_avx_right(*F, 13);                              // F <<< 19
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                           // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    T2 = T1 ^ T2;                                           // W[3]
    *D = *D + W;                                            // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                           // P0(TT2)
    *X0=_mm256_insert_epi32(*X0, T2, 0);                    // W[0],W[1],W[2],W[3]
}

void AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_1(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,\
__m256i *XFER, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, W, T0, T1;
    *XFER = _mm256_xor_si256(*X0, *X1);                     // WW
    t0 = rotate_avx_right(*A, 20);                              // A <<< 12
    t1 = *B | *C;                                           // B | C
    T0 = *B & *C;                                           // B & C
    T1 = *A & t1;                                           // A & (B | C)
    W = _mm256_extract_epi32(*X0, 3);                       // W[-16]
    t3 = Tj[*j];                                            // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                           // (A <<< 12) + E
    t5 = *F ^ *G;                                           // F ^ G
    t1 = T0 | T1;                                           // FF(A, B, C)
    t4 = t2 + t3;                                           // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                           // (F ^ G) & E
    *H = *H + W;                                            // H + Wj
    t4 = rotate_avx_right(t4, 25);                              // SS1
    t5 = t5 ^ *G;                                           // GG(E, F, G)
    *D = *D + t1;                                           // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                              // B <<< 9
    t1 = t4 + t5;                                           // GG(E, F, G) + SS1
    W = _mm256_extract_epi32(*XFER, 3);                     // WW[-16]
    t2 = t0 ^ t4;                                           // SS2
    *H = *H + t1;                                           // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                              // F <<< 19
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                           // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    *D = *D + W;                                            // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                           // P0(TT2)
}

void AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_2(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,__m256i *XFER, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5, W, T0, T1;
    t0 = rotate_avx_right(*A, 20);                              // A <<< 12
    t1 = *B | *C;                                           // B | C
    T0 = *B & *C;                                           // B & C
    T1 = *A & t1;                                           // A & (B | C)
    W = _mm256_extract_epi32(*X0, 2);                       
    t3 = Tj[*j];                                            // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                           // (A <<< 12) + E
    t5 = *F ^ *G;                                           // F ^ G
    t1 = T0 | T1;                                           // FF(A, B, C)
    t4 = t2 + t3;                                           // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                           // (F ^ G) & E
    *H = *H + W;                                            // H + Wj
    t4 = rotate_avx_right(t4, 25);                              // SS1
    t5 = t5 ^ *G;                                           // GG(E, F, G)
    *D = *D + t1;                                           // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                              // B <<< 9
    t1 = t4 + t5;                                           // GG(E, F, G) + SS1
    W = _mm256_extract_epi32(*XFER, 2); 
    t2 = t0 ^ t4;                                           // SS2
    *H = *H + t1;                                           // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                              // F <<< 19
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                           // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    *D = *D + W;                                            // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                           // P0(TT2)
}

void AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_3(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,__m256i *XFER, int *j) {
    uint32_t t0, t1, t2, t3, t4, t5, T0, T1, W;
    t0 = rotate_avx_right(*A, 20);                              // A <<< 12
    t1 = *B | *C;                                           // B | C
    t3 = Tj[*j];
    *j +=1;
    t2 = t0 + *E;                                           // (A <<< 12) + E
    T0 = *B & *C;                                           // B & C
    T1 = *A & t1;                                           // A & (B | C)
    W = _mm256_extract_epi32(*X0, 1);
    t5 = *F ^ *G;                                           // F ^ G
    t1 = T0 | T1;                                           // FF(A, B, C)
    t4 = t2 + t3;                                           // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                           // (F ^ G) & E
    *H = *H + W;                                            // H + Wj
    t4 = rotate_avx_right(t4, 25);                              // SS1
    t5 = t5 ^ *G;                                           // GG(E, F, G)
    *D = t1 + *D;                                           // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                              // B <<< 9
    t1 = t4 + t5;                                           // GG(E, F, G) + SS1
    W = _mm256_extract_epi32(*XFER, 1); 
    t2 = t0 ^ t4;                                           // SS2
    *H = *H + t1;                                           // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                              // F <<< 19
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                           // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    *D = *D + W;                                            // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                           // P0(TT2)
}

void AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_4(__m256i *X0, __m256i *X1, __m256i *X2, __m256i *X3, uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D,uint32_t *E, uint32_t *F, uint32_t *G, uint32_t *H,__m256i *XFER, int *j)
{
    uint32_t t0, t1, t2, t3, t4, t5;
    uint32_t T0, T1, W, WW;
    t0 = rotate_avx_right(*A, 20);                              // A <<< 12
    t1 = *B | *C;                                           // B | C
    t3 = Tj[*j];                                            // Tj <<< j
    *j +=1;
    t2 = t0 + *E;                                           // (A <<< 12) + E
    T0 = *B & *C;                                           // B & C
    T1 = *A & t1;                                           // A & (B | C)
    W = _mm256_extract_epi32(*X0, 0);                       // W[-16]
    t5 = *F ^ *G;                                           // F ^ G
    t1 = T0 | T1;                                           // FF(A, B, C)
    t4 = t2 + t3;                                           // (A <<< 12) + E + (Tj <<< j)
    t5 = t5 & *E;                                           // (F ^ G) & E
    *H = *H + W;                                            // H + Wj
    t4 = rotate_avx_right(t4, 25);                              // SS1
    t5 = t5 ^ *G;                                           // GG(E, F, G)
    *D = t1 + *D;                                           // FF(A, B, C) + D
    *B = rotate_avx_right(*B, 23);                              // B <<< 9
    t1 = t4 + t5;                                           // GG(E, F, G) + SS1
    W = _mm256_extract_epi32(*XFER, 0);                     // WW[-16]
    t2 = t0 ^ t4;                                           // SS2
    *H = *H + t1;                                           // TT2 = GG(E, F, G) + H + SS1 + Wj
    *F = rotate_avx_right(*F, 13);                              // F <<< 19
    t3 = rotate_avx_right(*H, 23);
    *D = *D + t2;                                           // FF(A, B, C) + D + SS2
    *H = *H ^ rotate_avx_right(*H, 15);
    *D = *D + W;                                            // TT1 = FF(A, B, C) + D + SS2 + W'j
    *H = *H ^ t3;                                           // P0(TT2)
}

void sm3_avx_compress(uint32_t digest[8], const uint8_t *buf, uint64_t nb) {
    uint32_t A,B,C,D,E,F,G,H;
    __m256i Digest = _mm256_loadu_si256((__m256i*)digest);
    
    A = _mm256_extract_epi32(Digest, 0);     
    B = _mm256_extract_epi32(Digest, 1);
    C = _mm256_extract_epi32(Digest, 2);
    D = _mm256_extract_epi32(Digest, 3);
    E = _mm256_extract_epi32(Digest, 4);
    F = _mm256_extract_epi32(Digest, 5);
    G = _mm256_extract_epi32(Digest, 6);
    H = _mm256_extract_epi32(Digest, 7);

    while (nb--) {
        __m256i M01 = _mm256_loadu_si256((__m256i*)buf);
        __m256i M23 = _mm256_loadu_si256((__m256i*)(buf + 32));

        __m128i m0 = _mm256_extracti128_si256(M01, 0);  
        __m128i m1 = _mm256_extracti128_si256(M01, 1); 
        __m128i m2 = _mm256_extracti128_si256(M23, 0);  
        __m128i m3 = _mm256_extracti128_si256(M23, 1);  
        __m256i X0 = _mm256_set_m128i(m0,m0);
        __m256i X1 = _mm256_set_m128i(m1,m1);
        __m256i X2 = _mm256_set_m128i(m2,m2);
        __m256i X3 = _mm256_set_m128i(m3,m3);

        buf += 64;                                        // for next turn
        int i = 1;
        char test = (*(char*)&i);
        if (test){
            const __m256i mask = _mm256_set_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
            );
            X0 = _mm256_shuffle_epi8(X0, mask);
            X1 = _mm256_shuffle_epi8(X1, mask);
            X2 = _mm256_shuffle_epi8(X2, mask);
            X3 = _mm256_shuffle_epi8(X3, mask);
        }
        int j=0;
        
        __m256i XFER; __m256i XTMP0; __m256i XTMP1;__m256i XTMP2; __m256i XTMP3; __m256i XTMP4; __m256i XTMP5;
        for (int i = 0; i < 4; i++) {
            // Print(A,B,C,D,E,F,G,H);
            // print_m256i(X0);print_m256i(X1);print_m256i(X2);print_m256i(X3);
            
            AVX_FIRST_16_ROUNDS_AND_SCHED_1(&X0, &X1, &X2, &X3, &A, &B, &C, &D, &E, &F, &G, &H, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            
            AVX_FIRST_16_ROUNDS_AND_SCHED_2(&X0, &X1, &X2, &X3, &D, &A, &B, &C, &H, &E, &F, &G, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            
            AVX_FIRST_16_ROUNDS_AND_SCHED_3(&X0, &X1, &X2, &X3, &C, &D, &A, &B, &G, &H, &E, &F, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);

            AVX_FIRST_16_ROUNDS_AND_SCHED_4(&X0, &X1, &X2, &X3, &B, &C, &D, &A, &F, &G, &H, &E, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            
            circular_avx_shift(&X0, &X1, &X2, &X3);
        }

        for (int i = 0; i < 9; i++) {
            
            AVX_SECOND_36_ROUNDS_AND_SCHED_1(&X0, &X1, &X2, &X3, &A, &B, &C, &D, &E, &F, &G, &H, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            
            AVX_SECOND_36_ROUNDS_AND_SCHED_2(&X0, &X1, &X2, &X3, &D, &A, &B, &C, &H, &E, &F, &G, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            
            AVX_SECOND_36_ROUNDS_AND_SCHED_3(&X0, &X1, &X2, &X3, &C, &D, &A, &B, &G, &H, &E, &F, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            
            AVX_SECOND_36_ROUNDS_AND_SCHED_4(&X0, &X1, &X2, &X3, &B, &C, &D, &A, &F, &G, &H, &E, &XFER, &XTMP0, &XTMP1, &XTMP2, &XTMP3, &XTMP4, &XTMP5,&j);
            
            circular_avx_shift(&X0, &X1, &X2, &X3);
        }

        for (int i = 0; i < 3; i++) {
            
            AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_1(&X0, &X1, &X2, &X3, &A, &B, &C, &D, &E, &F, &G, &H, &XFER,&j);
            
            AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_2(&X0, &X1, &X2, &X3, &D, &A, &B, &C, &H, &E, &F, &G, &XFER,&j);
            
            AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_3(&X0, &X1, &X2, &X3, &C, &D, &A, &B, &G, &H, &E, &F, &XFER,&j);
            
            AVX_THIRD_12_ROUNDS_WITHOUT_SCHED_4(&X0, &X1, &X2, &X3, &B, &C, &D, &A, &F, &G, &H, &E, &XFER,&j);
            
            circular_avx_shift(&X0, &X1, &X2, &X3);
        }
        __m256i Tmp = _mm256_set_epi32(H,G,F,E,D,C,B,A);
        Digest = _mm256_xor_si256(Digest, Tmp);
        
        A = _mm256_extract_epi32(Digest, 0);     
        B = _mm256_extract_epi32(Digest, 1);
        C = _mm256_extract_epi32(Digest, 2);
        D = _mm256_extract_epi32(Digest, 3);
        E = _mm256_extract_epi32(Digest, 4);
        F = _mm256_extract_epi32(Digest, 5);
        G = _mm256_extract_epi32(Digest, 6);
        H = _mm256_extract_epi32(Digest, 7);
    }

    _mm256_storeu_si256((__m256i*)digest, Digest);
}

#endif