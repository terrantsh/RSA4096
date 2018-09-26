/****************************************************************************************
Filename    : main.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-9-25 09:52:02
Description : Achieve RSA4096 algorithmic about using public key to encrypt and decrypt
*****************************************************************************************/
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "public.h"

int main(int argc, char const *argv[])
{
    clock_t start, finish;
    double  duration;
    start = clock();

    unsigned char input [256] = {0x22,0x21,0x12,0xed,0xf2,0xde,0x54}; // message to encrypt
    public_encrypt(input); // public key encrypt

    char base64[] = "ODc1MDcwNkI4QkE5QkIxOUU5MkY5OENEQjU3OTQ2OEY2QjI5MTg4MjRFRjA1ODQyMEQ1RjhDOUFEMjBFRThFOENGNzQ1ODI5NDFGQ0Y1MzRCOTlERUJFQkI5Q0M5QUMwOEJBRTBCMjgyMEY4N0VDNDdCNjhGMUQ3QTkwRTI1QTdFRTdEMTcxMDQ2MjA5MzBBRTgwM0FCQzZFNTNDNTc2NTc2RTcyNkZCMDYyQ0JCNDRBMjAzMTcwM0QwOTZFMjVDNjY3NEYzODA1RUM2MjBDRERGMzlFREVENUM3QjkyNzYyRjcxMkE0MzhBQjI3Q0U4QUYwMjk1NjNGNkM1QUQzNUJGOTI2QkIwM0I1RDQ4ODQxRkQzNDJBNjI3RkFGRkFCREIyNkU0QTFCOEY5QkFDRDdCOTU5OEE3RkI5MDczMkU3MTI5RjM5MTJERTBFNjk0NUYzRkNFRUQyMUM3RDMwRDY0NTU2MUM2M0IzQkQ1MDNEOUYwNTQ2Q0MzQjg4MDVGM0Q3QjQ4MzZDQTVCQ0ZFRDM4ODZENjUxQkExQzhEQ0IwQTEzMTEyQkYxNjdEOTU2MkQwNzQ1QTMxQkFBODE1OEVBMzQyRjY4NjAzNDBDQzRDREQ1N0FFQTQzMTJCMEM0QTZFNTRDNUE2NUI0RTlGREM3MjlBQzIyQTREQzI0QjdENDZGRTlENzhCMjQxNjU0NzM5NTAzOEY0MEM3NjQyQkNFM0QyOTExNDlCRkY3RUYyMUQ2QjU5MUU5NTVFN0MxN0MxMEY3QUFBRDA5OThFREIwQTUxQkVERDE5MzNCMTFGMjk1MDI0MjIzQzVGM0I3MUE2NjlEMDhBM0IyMTZEN0IyQTIzNkQyMUYzNkQxMzYzOUU2Q0ZBM0IyNTZEMjAyQTA2OTk3RTU5NzY2N0UzODcwM0Y5RDU5M0VBRTdBRDZCNDBEMDk2QUU1MzM0RkI2NzQyNTJCN0QwOUVDNUNBMzVGNDVEOTBGMDJCMzg4ODVFRkYwNjBFQUMyMDc5QTk3MzIyQ0UwNjE2RkJDNDFCNTYzRUUzNDlFMUE4RTI3RTU2M0E3Q0UzQjdBNDJFQUQ1M0UyQTFGQjRFN0MwMjQ5RjVDNUExQjcwRTA3QzM1MjQwMjMzODVCRTM2NDNCMkQxMjE1ODQ5OEUzMDBGOEY0MDE5OTI2REQ4RkFGODY2Njc2NDY4MUZFMDRENUEwQTNEOUYxMDNGOEE5MkI4QjFEMzgxRTI4MzJFODEyOTBDQ0ZCQjQ4QzkwMjBGRjJEODVEMDQzMjUzM0I2NjczN0QwNENDMDczMjQyREIyMTdBRjJDQ0IwRDYyNUFCQkE4M0I1MjE1OEQ2NEU4NjQ4RkM0RA==";
    public_decrypt(base64); // private key decrypt

    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;   // encrypt or decrypt time used
    printf( "%f seconds\n", duration );

    return 0;
}