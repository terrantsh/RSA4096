//
// Created by tansh on 2018/9/22.
//

#ifndef RSA_2048_BASE64_H
#define RSA_2048_BASE64_H

unsigned int str_hex(unsigned char *str,unsigned char *hex) ;
int base64_encode(const unsigned char * sourcedata, char * base64);
int base64_decode(const char * base64, unsigned char * dedata);

#endif //RSA_2048_BASE64_H
