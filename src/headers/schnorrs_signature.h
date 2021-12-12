#ifndef __SCHNORRS_SIGNATURE_H__
#define __SCHNORRS_SIGNATURE_H__

#include <globals.h>

struct SchnorrParams {
    unsigned char p[BUFFER];
    unsigned char q[BUFFER];
    unsigned char g[BUFFER];
};

struct SchnorrSignature {
    unsigned char hash[BUFFER];
    unsigned char signature[BUFFER];
    unsigned char r[BUFFER];
    unsigned char c_prime[BUFFER];
};

struct SchnorrKeychain {
    unsigned char pk[BUFFER];
    unsigned char sk[BUFFER];
};

extern DSA *dsa;

unsigned int gen_schnorr_params(struct SchnorrParams *params);
unsigned int gen_schnorr_keys(struct SchnorrKeychain *keys);
unsigned int schnorr_sign(struct SchnorrParams *params, unsigned char *sk, unsigned char *message, unsigned char *kappa, struct SchnorrSignature *signature);
unsigned int schnorr_verify(struct SchnorrParams *params, unsigned char *pk, unsigned char *message, unsigned char *kappa, struct SchnorrSignature *signature);
void free_schnorr_mem();

#endif