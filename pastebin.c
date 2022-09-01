#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "crypto/evp.h"
#include "crypto/sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>


#define TRY_TIMES 10000

void my_sm4encrpt(unsigned char * keyStr,unsigned char * surbuf,int surlen,unsigned char * enbuf, const EVP_CIPHER* mode)
{
    unsigned char *out_buf = enbuf;
    int out_len;
    int out_padding_len;
    int i;
    unsigned char *iv;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if(mode == EVP_sm4_ecb())
        EVP_EncryptInit(ctx, mode, keyStr, NULL);
    else
        EVP_EncryptInit(ctx, mode, keyStr, iv);
    
    out_len = 0;
    struct timeval st, ed;

    gettimeofday(&st, NULL);
    for(int i = 0 ; i < TRY_TIMES; ++i)
        EVP_EncryptUpdate(ctx, out_buf, &out_len, surbuf, surlen);
    gettimeofday(&ed, NULL);

    long int tt = (ed.tv_sec - st.tv_sec) * 1000000 + (ed.tv_usec - st.tv_usec);

    printf("%6.2lf ",(double)((double)TRY_TIMES * surlen)/(double)tt);


    EVP_CIPHER_CTX_free(ctx);
}


void my_sm4decrpt(unsigned char * keyStr,unsigned char * surbuf,int surlen,unsigned char * enbuf, const EVP_CIPHER* mode)
{
    unsigned char *out_buf = enbuf;
    int out_len;
    int out_padding_len;
    int i;
    unsigned char *iv;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if(mode == EVP_sm4_ecb())
        EVP_DecryptInit(ctx, mode, keyStr, NULL);
    else
        EVP_DecryptInit(ctx, mode, keyStr, iv);
    
    out_len = 0;
    struct timeval st, ed;

    gettimeofday(&st, NULL);
    for(int i = 0 ; i < TRY_TIMES; ++i)
        EVP_DecryptUpdate(ctx, out_buf, &out_len, surbuf, surlen);
    gettimeofday(&ed, NULL);

    long int tt = (ed.tv_sec - st.tv_sec) * 1000000 + (ed.tv_usec - st.tv_usec);

    printf("%6.2lf ",(double)((double)TRY_TIMES * surlen)/(double)tt);


    EVP_CIPHER_CTX_free(ctx);
}




int main(){
    unsigned char keyStr[16]={0x15,0x67,0x28,0xe1,0x5f,0x9a,0xfc,0x01,0xd4,0xb6,0x1b,0x4e,0x44,0x5d,0xbb,0x26};
    
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t simdin[5000], simdout[5000];
    for(int i = 0; i < 5000; ++i){
        simdin[i] = i & 0xff;
    }

    int index[7] = {16, 64, 128, 256, 1024, 1420, 4096};

    printf("warm up cpu\n");
    for(int i = 0 ; i < 7; ++i){
        my_sm4encrpt(key, simdin, index[i], simdout, EVP_sm4_ecb());
    }puts("");

    printf("ecb enc ");
    for(int i = 0 ; i < 7; ++i){
        my_sm4encrpt(key, simdin, index[i], simdout, EVP_sm4_ecb());
    }puts("");

    printf("ecb dec ");
    for(int i = 0 ; i < 7; ++i){
        my_sm4decrpt(key, simdin, index[i], simdout, EVP_sm4_ecb());
    }puts("");

    printf("cbc enc ");
    for(int i = 0 ; i < 7; ++i){
        my_sm4encrpt(key, simdin, index[i], simdout, EVP_sm4_cbc());
    }puts("");

    printf("cbc dec ");
    for(int i = 0 ; i < 7; ++i){
        my_sm4decrpt(key, simdin, index[i], simdout, EVP_sm4_cbc());
    }puts("");

    printf("ctr enc ");
    for(int i = 0 ; i < 7; ++i){
        my_sm4encrpt(key, simdin, index[i], simdout, EVP_sm4_ctr());
    }puts("");

    printf("ctr dec ");
    for(int i = 0 ; i < 7; ++i){
        my_sm4decrpt(key, simdin, index[i], simdout, EVP_sm4_ctr());
    }puts("");

    return 0;
}
