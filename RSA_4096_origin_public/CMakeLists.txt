cmake_minimum_required(VERSION 3.12)
project(RSA_2048 C)

set(CMAKE_C_STANDARD 99)

add_executable(RSA_2048 main.c bignum.h rsa.c rsa.h keys.h bignum.c public.c public.h base64.c base64.h)