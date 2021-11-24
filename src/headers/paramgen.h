#ifndef __PARAM_GEN_H__
#define __PARAM_GEN_H__

extern unsigned int g_upper;
extern unsigned int g_lower;
#define BUFFER 100

unsigned int genPrime();
int genGenerators(unsigned int q, unsigned int *arr);
int valueInArray(unsigned int val, int size, unsigned int *arr);
unsigned int modular_pow(unsigned int base, unsigned int exponent, unsigned int modulus);

#endif