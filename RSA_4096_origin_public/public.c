//
// Created by tansh on 2018/9/22.
//
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "rsa.h"
#include "keys.h"
#include "public.h"
#include "base64.h"

void print_array(char *TAG, uint8_t *array, int len)
{
    int i;

    printf("%s[%d]: ", TAG, len);
    for(i=0; i<len; i++) {
        printf("%02X", array[i]);
    }
    printf("\n");
}

int public_encrypt(uint8_t input[256])
{

    rsa_pk_t pk = {0};
    uint8_t  output[512];
    uint32_t outputLen;
    uint8_t  inputLen;

    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));

    inputLen = strlen((const char *)input);
    print_array("Input_message", input, inputLen);
    printf("\n");

    // public key encrypt
    rsa_public_encrypt(output, &outputLen, input, inputLen, &pk);
    print_array("Public_key_encrypt", output, outputLen);
    printf("\n");

    // base64 encode
    unsigned char buffer[1024];
    for(int i = 0; i<outputLen; i++) {
        sprintf(buffer+2*i, "%02X", (unsigned char) output[i]);
    }
    const unsigned char *sourcedata = buffer ;
    char base64[2048];
    base64_encode(sourcedata, base64);// encode
    printf("ENC: %s\n",base64);
    printf("\n");

    return 0;
}

int public_decrypt(char base64[])
{
    rsa_pk_t pk = {0};
    unsigned char msg [512];
    uint32_t msg_len;

    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));

    // public key decrypt

    // base64 decode
    char dedata[2048];
    base64_decode(base64, (unsigned char*)dedata);// decode
    printf("DEC: %s", dedata);
    printf("\n");

    uint8_t str1[512];
    str_hex(dedata,str1);

    // public key decrypt
    rsa_public_decrypt(msg, &msg_len, str1, sizeof(str1), &pk);
    print_array("Public_key_decrypt", msg, msg_len);

    return 0;
}

