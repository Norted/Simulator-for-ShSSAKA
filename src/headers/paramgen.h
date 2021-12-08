#ifndef __PARAM_GEN_H__
#define __PARAM_GEN_H__

extern unsigned int g_upper;
extern unsigned int g_lower;

unsigned int genPrime(unsigned char *n);
//int genGenerators(unsigned int q, unsigned int *arr);
int valueInArray(unsigned int val, int size, unsigned int *arr);

#endif