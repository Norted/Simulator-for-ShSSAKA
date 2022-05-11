#ifndef __SCHNORRS_SIGNATURE_H__
#define __SCHNORRS_SIGNATURE_H__

#include <support_functions.h>
#include <SSAKA.h>
#include <globals.h>

unsigned int gen_schnorr_keychain(const EC_GROUP *group, struct schnorr_Keychain *keychain);
unsigned int schnorr_sign(struct schnorr_Keychain *params, const BIGNUM *sk, BIGNUM *message, EC_POINT *kappa, struct schnorr_Signature *signature);
unsigned int schnorr_verify(struct schnorr_Keychain *params, const EC_POINT *pk, BIGNUM *message, EC_POINT *kappa, struct schnorr_Signature *signature);

void free_schnorr_keychain(struct schnorr_Keychain *keys);
void init_schnorr_signature(const EC_GROUP *group, struct schnorr_Signature *signature);
void free_schnorr_signature(struct schnorr_Signature *signature);

#endif