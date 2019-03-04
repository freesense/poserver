
#include 	<stdio.h>
#include  <memory.h>
#include 	<string.h>

#include "GY_3DES_CRYPT.h"

/*
 * The 8 selection functions.
 * For some reason, they give a 0-origin
 * index, unlike everything else.
 */
static  unsigned char const XM_S[8][64] = {
    {14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
     0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
     4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
    15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13},

    {15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
     3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
     0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
    13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9},

    {10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
    13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
    1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12},

     {7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
    13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
    10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
    3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14},

     {2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
    14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
     4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
    11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3},

    {12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
    10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
     9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
    4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13},

     {4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
    13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
     1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
    6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12},

    {13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
     1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
     7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
    2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}
};

/*
 * P is a permutation on the selected combination
 * of the current L and key.
 */
static  unsigned char const XM_P[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
};

static  unsigned char const XM_IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
};

/*
 * Final permutation, FP = IP^(-1)
 */
static  unsigned char const  XM_FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
};

/*
 * Permuted-choice 1 from the key bits
 * to yield C and D.
 * Note that bits 8,16... are left out:
 * They are intended for a parity check.
 */
static  unsigned char const  XM_PC1_C[] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
};

static  unsigned char   XM_PC1_D[] = {
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
};

/*
 * Sequence of shifts used for the key schedule.
*/
static  unsigned char const  XM_shifts[] = {
    1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1,
};

/*
 * Permuted-choice 2, to pick out the bits from
 * the CD array that generate the key schedule.
 */
static  unsigned char const  XM_PC2_C[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
};

static  unsigned char const  XM_PC2_D[] = {
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

static  unsigned char const  XM_e[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
};

static unsigned char const toASCI[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static inline
int memxor (unsigned char *result, unsigned char const* field1, unsigned char const* field2, int length) {

    int   i;
    for ( i = 0; i < length; i++ )
        result[i] = ( field1[i] ^ field2[i] );
    return (0);
}

static inline
void Do_XOR(unsigned char *dest, unsigned char const*source, int size) {

    int i;
    for(i=0; i<size; i++)
        dest[i] ^= source[i];
}

void bcd_to_asc(unsigned char const* src, unsigned char* dst, int srclen) {
#define ds_to_char(x) ((x)>9?(x)+'A'-10:(x)+'0')
    int i;
    unsigned char d;
    for(i = 0; i < srclen; i++) {
        d = src[i] >> 4;
        *dst++ = ds_to_char(d);
        d = src[i] & 0x0F;
        *dst++ = ds_to_char(d);
    }
}

static inline
unsigned char __ord(char c) {
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= '0' && c <= '9')
        return c - '0';
    return 0;
}
int asc_to_bcd(unsigned char const* src, unsigned char* dst, int dstlen) {

    int i;
    unsigned char d;
    for(i = 0; i<dstlen; i++) {
        d = __ord(src[i*2]);
        d <<= 4;
        d += __ord(src[i*2+1]);
        *dst++ = d;
    }
    return 0;
}

/*
** 	compress is the inverse of expand
**	it converts a 64 character bit stream into eight characters.
*/
static inline
void XM_compress(unsigned char const*in, unsigned char *out) {
    int	temp;
    int	i,j;

    for(i=0;i<8;i++){
        out[i] = 0;
        temp = 1;
        for (j=7;j>=0;j--){
            out[i] = out[i] + ( in[i*8+j] * temp);
            temp *= 2;
        }
    }
}

/*
 * Set up the key schedule from the key.
 */
static inline
void XM_setkey(unsigned char const*key, unsigned char* XM_KS) {

    register int i, j, k;
    int t;
    //The C and D arrays used to calculate the key schedule.
    unsigned char   XM_C[28];
    unsigned char   XM_D[28];
    /*
     * First, generate C and D by permuting
     * the key.  The low order bit of each
     * 8-bit unsigned char is not used, so C and D are only 28
     * bits apiece.
     */
    for (i=0; i<28; i++) {
        XM_C[i] = key[XM_PC1_C[i]-1];
        XM_D[i] = key[XM_PC1_D[i]-1];
    }

    /*
     * To generate Ki, rotate C and D according
     * to schedule and pick up a permutation
     * using PC2.
     */
    for (i=0; i<16; i++) {
        /*
         * rotate.
         */
        for (k=0; k<XM_shifts[i]; k++) {
            t = XM_C[0];
            for (j=0; j<28-1; j++)
                XM_C[j] = XM_C[j+1];

            XM_C[27] = t;
            t = XM_D[0];

            for (j=0; j<28-1; j++)
                XM_D[j] = XM_D[j+1];

            XM_D[27] = t;
        }
        /*
         * get Ki. Note C and D are concatenated.
         */
        for (j=0; j<24; j++) {
            XM_KS[i*48+j] = XM_C[XM_PC2_C[j]-1];
            XM_KS[i*48+j+24] = XM_D[XM_PC2_D[j]-28-1];
        }
    }
}

/*
 * The payoff: encrypt a block.
 */
static inline
void XM_encrypt(unsigned char *block, int edflag, unsigned char* XM_E, unsigned char* XM_KS) {
    int i, ii;
    int t, j, k;
    unsigned char   XM_tempL[32];
    unsigned char   XM_f[32];

    //The current block, divided into 2 halves.
    unsigned char XM_L[64];
    unsigned char* XM_R = &XM_L[32];


    // The combination of the key and the input, before selection.
    unsigned char   XM_preS[48];

    //First, permute the bits in the input
    for (j=0; j<64; j++)
        XM_L[j] = block[XM_IP[j]-1];

    for (j=0; j < 32; j++)
        XM_R[j] = XM_L[j+32];

    // Perform an encryption operation 16 times.
    for (ii=0; ii<16; ii++) {
        /*
         * Set direction
         */
        if (edflag)
            i = 15-ii;
        else
            i = ii;
        /*
         * Save the R array,
         * which will be the new L.
         */
        for (j=0; j<32; j++)
            XM_tempL[j] = XM_R[j];

        /*
         * Expand R to 48 bits using the E selector;
         * exclusive-or with the current key bits.
         */
        for (j=0; j<48; j++)
            XM_preS[j] = XM_R[XM_E[j]-1] ^ XM_KS[i*48+j];

        /*
         * The pre-select bits are now considered
         * in 8 groups of 6 bits each.
         * The 8 selection functions map these
         * 6-bit quantities into 4-bit quantities
         * and the results permuted
         * to make an f(R, K).
         * The indexing into the selection functions
         * is peculiar; it could be simplified by
         * rewriting the tables.
         */
        for (j=0; j<8; j++) {
            t = 6*j;
            k = XM_S[j][(XM_preS[t+0]<<5)+
                    (XM_preS[t+1]<<3)+
                    (XM_preS[t+2]<<2)+
                    (XM_preS[t+3]<<1)+
                    (XM_preS[t+4]<<0)+
                    (XM_preS[t+5]<<4)];
            t = 4*j;
            XM_f[t+0] = (k>>3)&0x01;
            XM_f[t+1] = (k>>2)&0x01;
            XM_f[t+2] = (k>>1)&0x01;
            XM_f[t+3] = (k>>0)&0x01;
        }

        /*
         * The new R is L ^ f(R, K).
         * The f here has to be permuted first, though.
         */
        for (j=0; j<32; j++)
            XM_R[j] = XM_L[j] ^ XM_f[XM_P[j]-1];
        /*
         * Finally, the new L (the original R)
         * is copied back.
         */
        for (j=0; j<32; j++)
            XM_L[j] = XM_tempL[j];

    }
    /*
     * The output L and R are reversed.
     */
    for (j=0; j<32; j++) {
        t = XM_L[j];
        XM_L[j] = XM_R[j];
        XM_R[j] = t;
    }

    for (j=32;j<64;j++)
        XM_L[j] = XM_R[j-32];

    /*
     * The final output
     * gets the inverse permutation of the very original.
     */
    for (j=0; j<64; j++)
        block[j] = XM_L[XM_FP[j]-1];
}

/*
**	expand takes the eight character string in
**	and converts it to a 64 character array containing
**	zero or one (bit stream).
*/
static inline
void XM_expand(unsigned char const*in,unsigned char *out) {

    int	i,j;

    for (i=0;i<8;i++){
        for (j=0; j<8; j++) {
            *out = (in[i] <<j) & 0x80;
            if (*out == 0x80)
                *out = 0x01;
            out++;
        }
    }
}

static inline
void des_encrypt(unsigned char const*key, unsigned char* inoutput, int len, int ed_flag)
{
    int	i;
    unsigned char	bits[64];
    //The key schedule.Generated from the key.
    unsigned char   XM_KS[16*48];
    //The E bit-selection table.
    unsigned char   XM_E[48];

    XM_expand(key,bits);
    XM_setkey(bits, XM_KS);

    for(i=0;i<48;i++)
        XM_E[i] = XM_e[i];

    /***********************************************************************
     Because DES can only encrypt 8 bytes, we divide the data into several
     pieces of 8 bytes to encrypt
    ***********************************************************************/
    while (len >= 8) {
        XM_expand (inoutput, bits);     /* expand to bit stream */
        XM_encrypt(bits, ed_flag, XM_E, XM_KS);    /* encrypt */
        XM_compress(bits, inoutput);    /* compress to 8 characters */
        inoutput += 8;
        len -= 8;
    }

    for (i = 0; i < len; i++)  inoutput[i] ^= key[i];
}

/**********************************************
 Use DES algoritm to encrypt or decrypt data
 if ed_flag is ENCRYPT, it encrypts data
 if ed_flag is DECRYPT, it decrypts data
***********************************************/
void DES_encrypt(unsigned char const*key, unsigned char const*input, int in_len, unsigned char *output, int ed_flag)
{
    memcpy(output, input, in_len);

    des_encrypt(key, output, in_len, ed_flag);
}

int DES3_encrypt(unsigned char const*key, unsigned char const*input, int len, unsigned char *output)
{
    unsigned char szkey[9];

    szkey[8]=0;

    //1.begin MAB的3DES加密
    /**********************************************
     if ed_flag is ENCRYPT<0>, it encrypts data
     if ed_flag is DECRYPT<1>, it decrypts data
    ***********************************************/
    memcpy(output, input, len);
    memcpy(szkey, key, 8);
    des_encrypt(szkey, output, len, ENCRYPT);

    memcpy(szkey, key + 8, 8);
    des_encrypt(szkey, output, len, DESCRYPT);

    memcpy(szkey, key, 8);
    des_encrypt(szkey, output, len, ENCRYPT);
    //1.end MAB的3DES加密

    return 0;
}

//3DES解密
int DES3_decrypt(unsigned char const*key, unsigned char const*input, int len, unsigned char *output)
{
    unsigned char szkey[8] = {0};

    //1.begin MAB的3DES加密
    /**********************************************
     if ed_flag is ENCRYPT<0>, it encrypts data
     if ed_flag is DECRYPT<1>, it decrypts data
    ***********************************************/
    memcpy(output, input, len);
    memcpy(szkey, key, 8);
    des_encrypt(szkey, output, len, DESCRYPT);

    memcpy(szkey, key + 8, 8);
    des_encrypt(szkey, output, len, ENCRYPT);

    memcpy(szkey, key, 8);
    des_encrypt(szkey, output, len, DESCRYPT);
    //1.end MAB的3DES加密

    return 0;
}

/***********************************************************************
 *      编    号:
 *      函 数 名:void    DES3_Mac
 *      入口参数: buf
 *		  len 报文长度
 *
 *      返回参数: 函数返回>=0表示打包成功
 *
 *      函数功能: 生成报文MAC
 ***********************************************************************/
//mac加密
void DES3_Mac(unsigned char const* key, unsigned char const* buf, int len, unsigned char* mac)
{
    unsigned char pszTmp[8], pszTmpMac[8];
    unsigned char buff[16];
    int i;

    memset(pszTmpMac, 0, sizeof(pszTmpMac));

    for(i=0;i<len;i+=8) {
        if(len-i >= 8)
            memcpy(pszTmp, buf + i, sizeof(pszTmp));
        else {
            memset(pszTmp, 0, sizeof(pszTmp));
            memcpy(pszTmp, buf + i, len - i);
        }
        Do_XOR(pszTmpMac, pszTmp, 8);
    }
    bcd_to_asc(pszTmpMac, buff, 8);
    memcpy(pszTmp, buff, 8);//前8字节
    memcpy(pszTmpMac, buff+8, 8);//后8字节

    des_encrypt(key, pszTmp, 8, ENCRYPT);
    Do_XOR(pszTmp, pszTmpMac, 8);			//加密结果与后8字节异或
    des_encrypt(key, pszTmp, 8, ENCRYPT);

    memcpy(mac, pszTmp, 8);
}
