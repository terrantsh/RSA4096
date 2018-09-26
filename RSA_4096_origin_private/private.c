//
// Created by tansh on 2018/9/22.
//
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "private.h"
#include "rsa.h"
#include "keys.h"
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

int private_encrypt(uint8_t input[256])
{
    rsa_pk_t pk = {0};
    rsa_sk_t sk = {0};
    uint8_t  output[512];
    uint32_t outputLen;
    uint8_t  inputLen;

    printf("RSA encryption method is beginning!\n");
    printf("\n");
    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    sk.bits = KEY_M_BITS;
    memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)], key_pe, sizeof(key_pe));
    memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN-sizeof(key_p1)],   key_p1, sizeof(key_p1));
    memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN-sizeof(key_p2)],   key_p2, sizeof(key_p2));
    memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN-sizeof(key_e1)],   key_e1, sizeof(key_e1));
    memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN-sizeof(key_e2)],   key_e2, sizeof(key_e2));
    memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN-sizeof(key_c)],    key_c,  sizeof(key_c));

    inputLen = strlen((const char *)input);
    print_array("Input_message", input, inputLen);
    printf("\n");

    // private key encrypt
    rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);
    print_array("Private_key_encrypt", output, outputLen);

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

int private_decrypt(char base64[])
{
    rsa_pk_t pk = {0};
    rsa_sk_t sk = {0};
    unsigned char msg [512];
    uint32_t msg_len;

    pk.bits = KEY_M_BITS;
    memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    sk.bits = KEY_M_BITS;
    memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m)],  key_m,  sizeof(key_m));
    memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e)],  key_e,  sizeof(key_e));
    memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)], key_pe, sizeof(key_pe));
    memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN-sizeof(key_p1)],   key_p1, sizeof(key_p1));
    memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN-sizeof(key_p2)],   key_p2, sizeof(key_p2));
    memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN-sizeof(key_e1)],   key_e1, sizeof(key_e1));
    memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN-sizeof(key_e2)],   key_e2, sizeof(key_e2));
    memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN-sizeof(key_c)],    key_c,  sizeof(key_c));

    // public key decrypt
    // base64 decode
    char dedata[2048];
    base64_decode(base64, (unsigned char*)dedata);// decode
    printf("DEC: %s", dedata);
    printf("\n");

    uint8_t str1[512];
    str_hex(dedata,str1);

    rsa_private_decrypt(msg, &msg_len, str1, sizeof(str1), &sk);
    print_array("Private_key_decrypt", msg, msg_len);

    return 0;
}


