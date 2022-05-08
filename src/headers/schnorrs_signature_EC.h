#ifndef __SCHNORRS_SIGNATURE_EC_H__
#define __SCHNORRS_SIGNATURE_EC_H__

#include <support_functions.h>
#include <SSAKA.h>
#include <globals.h>

unsigned int gen_ec_schnorr_params(DSA *dsa, struct EC_schnorr_Params *params);
unsigned int gen_ec_schnorr_keys(DSA *dsa, struct EC_schnorr_Keychain *keys);
unsigned int ec_schnorr_sign(struct EC_schnorr_Params *params, BIGNUM *sk, BIGNUM *message, BIGNUM *kappa, struct EC_schnorr_Signature *signature);
unsigned int ec_schnorr_verify(struct EC_schnorr_Params *params, BIGNUM *pk, BIGNUM *message, BIGNUM *kappa, struct EC_schnorr_Signature *signature);

void init_ec_schnorr_params(struct EC_schnorr_Params *params);
void free_ec_schnorr_params(struct EC_schnorr_Params *params);
void init_ec_schnorr_keychain(struct EC_schnorr_Keychain *keys);
void free_ec_schnorr_keychain(struct EC_schnorr_Keychain *keys);
void init_ec_schnorr_signature(struct EC_schnorr_Signature *signature);
void free_ec_schnorr_signature(struct EC_schnorr_Signature *signature);

#endif