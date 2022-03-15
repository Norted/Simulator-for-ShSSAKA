#ifndef __SCHNORRS_SIGNATURE_H__
#define __SCHNORRS_SIGNATURE_H__

#include <globals.h>

struct schnorr_Params {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
};

struct schnorr_Signature {
    BIGNUM *hash;
    BIGNUM *signature;
    BIGNUM *r;
    BIGNUM *c_prime;
};

struct schnorr_Keychain {
    BIGNUM *pk;
    BIGNUM *sk;
};

extern DSA *dsa;

unsigned int gen_schnorr_params(struct schnorr_Params *params);
unsigned int gen_schnorr_keys(struct schnorr_Keychain *keys);
unsigned int schnorr_sign(struct schnorr_Params *params, BIGNUM *sk, BIGNUM *message, BIGNUM *kappa, struct schnorr_Signature *signature);
unsigned int schnorr_verify(struct schnorr_Params *params, BIGNUM *pk, BIGNUM *message, BIGNUM *kappa, struct schnorr_Signature *signature);
void free_schnorr_mem();

#endif