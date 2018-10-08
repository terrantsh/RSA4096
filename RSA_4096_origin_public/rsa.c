/*****************************************************************************
Filename    : rsa.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-9-25 09:56:36
Description : RSA encrypted function
*****************************************************************************/
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "rsa.h"
#include "bignum.h"

static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk);

void generate_rand(uint8_t *block, uint32_t block_len)
{
    uint32_t i;
    for(i=0; i<block_len; i++) {
        srand ((unsigned)time(NULL));   // real rand message
        block[i] = rand();
    }
}

int rsa_public_encrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    int status;
    uint8_t byte, pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len;

    modulus_len = (pk->bits + 7) / 8;
    if(in_len + 11 > modulus_len) {
        return ERR_WRONG_LEN;
    }

    pkcs_block[0] = 0;
    pkcs_block[1] = 2;
    for(i=2; i<modulus_len-in_len-1; i++) {
        do {
            generate_rand(&byte, 1);
        } while(byte == 0);
        pkcs_block[i] = byte;
    }
    pkcs_block[i++] = 0;

    memcpy((uint8_t *)&pkcs_block[i], (uint8_t *)in, in_len);
    status = public_block_operation(out, out_len, pkcs_block, modulus_len, pk);
    // Clear potentially sensitive information
    byte = 0;
    memset((uint8_t *)pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

int rsa_public_decrypt(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk) {
    int status;
    uint8_t pkcs_block[RSA_MAX_MODULUS_LEN];
    uint32_t i, modulus_len, pkcs_block_len;

    modulus_len = (pk->bits + 7) / 8;
    if (in_len > modulus_len)
        return ERR_WRONG_LEN;

    status = public_block_operation(pkcs_block, &pkcs_block_len, in, in_len, pk);
    if (status != 0)
        return status;

    if (pkcs_block_len != modulus_len)
        return ERR_WRONG_LEN;

    if ((pkcs_block[0] != 0) || (pkcs_block[1] != 1))
        return ERR_WRONG_DATA;

    for (i = 2; i < modulus_len - 1; i++) {
        if (pkcs_block[i] != 0xFF) break;
    }

    if (pkcs_block[i++] != 0)
        return ERR_WRONG_DATA;

    *out_len = modulus_len - i;
    if (*out_len + 11 > modulus_len)
        return ERR_WRONG_DATA;

    memcpy((uint8_t *) out, (uint8_t *) &pkcs_block[i], *out_len);

    // Clear potentially sensitive information
    memset((uint8_t *) pkcs_block, 0, sizeof(pkcs_block));

    return status;
}

static int public_block_operation(uint8_t *out, uint32_t *out_len, uint8_t *in, uint32_t in_len, rsa_pk_t *pk)
{
    uint32_t edigits, ndigits;
    bn_t c[BN_MAX_DIGITS], e[BN_MAX_DIGITS], m[BN_MAX_DIGITS], n[BN_MAX_DIGITS];

    bn_decode(m, BN_MAX_DIGITS, in, in_len);
    bn_decode(n, BN_MAX_DIGITS, pk->modulus, RSA_MAX_MODULUS_LEN);
    bn_decode(e, BN_MAX_DIGITS, pk->exponent, RSA_MAX_MODULUS_LEN);

    ndigits = bn_digits(n, BN_MAX_DIGITS);
    edigits = bn_digits(e, BN_MAX_DIGITS);

    if(bn_cmp(m, n, ndigits) >= 0) {
        return ERR_WRONG_DATA;
    }

    bn_mod_exp(c, m, e, edigits, n, ndigits);

    *out_len = (pk->bits + 7) / 8;
    bn_encode(out, *out_len, c, ndigits);

    // Clear potentially sensitive information
    memset((uint8_t *)c, 0, sizeof(c));
    memset((uint8_t *)m, 0, sizeof(m));

    return 0;
}
