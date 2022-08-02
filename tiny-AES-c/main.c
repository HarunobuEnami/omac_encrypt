#include<stdio.h>
#include "aes.h"
static void phex(uint8_t* str);
int main(void)

{
    struct AES_ctx ctx;
    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    uint8_t in[4]  = { 0x87, 0x4d, 0x61, 0x91};
    AES_init_ctx_iv(&ctx, key, iv);
    phex(in);
    AES_CTR_xcrypt_buffer(&ctx, in, 4); //ここに突っ込むと2番目に暗号化されたデータが出てくる(使用するAES_ctx構造体，平文or暗号文，それのバイト長)
    phex(in);
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, in, 4); //復号化
    phex(in);
}

static void phex(uint8_t* str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}