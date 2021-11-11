#ifndef __PAILLIER_H__
#define __PAILLIER_H__

struct paillierKeyring {
    struct paillierPrivateKey sk;
    struct paillierPublicKey pk;
};

struct paillierPrivateKey {
    unsigned long long l;
    unsigned long long m;
};

struct paillierPublicKey {
    unsigned long long n;
    unsigned long long n_sq;
    unsigned long long g;
};

unsigned long long invmod(unsigned long long a, unsigned long long p);
unsigned long long modpow(unsigned long long base, unsigned long long exponent, unsigned long long modulus);
struct paillierKeyring generate_keypair(unsigned long long bits);
unsigned long long encrypt(struct paillierPublicKey pk, unsigned long long plain);
unsigned long long e_add(struct paillierPublicKey pk, unsigned long long a, unsigned long long b);
unsigned long long e_const(struct paillierPublicKey pk, unsigned long long a, unsigned long long n, char unsigned operation);
unsigned long long decrypt(struct paillierKeyring keyring, unsigned long long cipher);

#endif