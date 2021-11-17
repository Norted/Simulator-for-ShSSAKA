#ifndef __PRIMES_H__
#define __PRIMES_H__

extern const unsigned long long smallprimes[];
#define MAX 100000

void ipow(unsigned long long * values, unsigned long long a, unsigned long long b, unsigned long long n);
int rabin_miller_witness(unsigned long long test, unsigned long long possible, int bits);
unsigned long long default_k(int bits);
int is_probably_prime(unsigned long long possible, int bits);
unsigned long long generate_prime(int bits);
unsigned long long _binpow(unsigned long long base, unsigned long long exp, unsigned long long mod);

#endif