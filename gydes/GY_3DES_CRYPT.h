#ifndef GY_3DES_CRYPT1_H
#define GY_3DES_CRYPT1_H
#include <stdio.h>
#include <memory.h>
#include <string.h>

#define		ENCRYPT		0
#define		DESCRYPT	1

#ifdef __cplusplus
extern "C" {
#endif

void bcd_to_asc(unsigned char const* src, unsigned char* dst, int srclen);
int asc_to_bcd(unsigned char const*src, unsigned char *dst, int dstlen);

//DESӽ
void DES_encrypt(unsigned char const*key, unsigned char const*input, int in_len, unsigned char *output, int ed_flag);
//3DESӽ
int DES3_encrypt(unsigned char const*key, unsigned char const*input, int len, unsigned char *output);
int DES3_decrypt(unsigned char const*key, unsigned char const*input, int len, unsigned char *output);

//3DESMAC
void DES3_Mac(unsigned char const* key, unsigned char const* data, int len, unsigned char *mac);

#ifdef __cplusplus
}
#endif

#endif // GY_3DES_CRYPT1_H
