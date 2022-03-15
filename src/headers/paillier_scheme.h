#ifndef __SCHEME3_H__
#define __SCHEME3_H__

#include <globals.h>

struct paillier_PrivateKey
{
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *lambda; // lambda (for scheme 1) or alpha (for scheme 3)
    BIGNUM *mi;     // modular multiplicative inverse (L(g^lambda mod n^2))^(-1) mod n
};

struct paillier_PublicKey
{
    BIGNUM *n;
    BIGNUM *n_sq;
    BIGNUM *g;
};

struct paillier_Keychain
{
    struct paillier_PrivateKey sk;
    struct paillier_PublicKey *pk;
};

unsigned int paillier_generate_keypair(struct paillier_Keychain *keychain);
unsigned int paillier_encrypt(struct paillier_PublicKey *pk, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise);
unsigned int paillier_decrypt(struct paillier_Keychain *keychain, BIGNUM *cipher, BIGNUM *plain);

unsigned int homomorphy_add(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *b, BIGNUM *res);
unsigned int homomorphy_add_const(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);
unsigned int homomorphy_mul_const(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);

#endif