#ifndef __PAILLIER_H__
#define __PAILLIER_H__

#include <stdio.h>
#include <math.h>

struct paillierPrivateKey {
    unsigned long long l;
    unsigned long long m;
};

struct paillierPublicKey {
    unsigned long long n;
    unsigned long long n_sq;
    unsigned long long g;
};

struct paillierKeyring {
    struct paillierPrivateKey sk;
    struct paillierPublicKey pk;
};


extern const unsigned int smallprimes[];
#define MAXITER 10000
#define SEED    42

unsigned long long invmod(unsigned long long a, unsigned long long p);
struct paillierKeyring generate_keypair();
unsigned long long encrypt(struct paillierPublicKey pk, unsigned long long plain);
unsigned long long decrypt(struct paillierKeyring keyring, unsigned long long cipher);
unsigned long long modpow(unsigned long long base, unsigned long long exp, unsigned long long mod);
unsigned long long gcd (unsigned long long a, unsigned long long b);
unsigned long long add(struct paillierPublicKey pk, unsigned long long a, unsigned long long b);
unsigned long long add_const(struct paillierPublicKey pk, unsigned long long a, unsigned long long n);
unsigned long long mul_const(struct paillierPublicKey pk, unsigned long long a, unsigned long long n);
#endif