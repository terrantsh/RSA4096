//
// Created by tansh on 2018/9/22.
//
#ifndef RSA_2048_PUBLIC_H
#define RSA_2048_PUBLIC_H

#include <stdint.h>
int public_encrypt(uint8_t input[256]);
int public_decrypt(char base64[]);

#endif //RSA_2048_PUBLIC_H