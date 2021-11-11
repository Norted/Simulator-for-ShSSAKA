#ifndef __PRIMES_H__
#define __PRIMES_H__

int smallprimes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97};

int ipow(int a, int b, int n);
int rabin_miller_witness(test, possible);
int default_k(int bits);
int is_probably_prime(int possible, int k);
int generate_prime(int bits, int k);

#endif