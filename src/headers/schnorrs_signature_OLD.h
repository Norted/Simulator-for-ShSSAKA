#ifndef __SCHNORRS_SIGNATURE_H__
#define __SCHNORRS_SIGNATURE_H__

#include <support_functions.h>
#include <SSAKA_OLD.h>
#include <globals.h>


unsigned int gen_schnorr_params(DSA *dsa, struct schnorr_Params *params);
unsigned int gen_schnorr_keys(DSA *dsa, struct schnorr_Keychain *keys);
unsigned int schnorr_sign(struct schnorr_Params *params, BIGNUM *sk, BIGNUM *message, BIGNUM *kappa, struct schnorr_Signature *signature);
unsigned int schnorr_verify(struct schnorr_Params *params, BIGNUM *pk, BIGNUM *message, BIGNUM *kappa, struct schnorr_Signature *signature);

void init_schnorr_params(struct schnorr_Params *params);
void free_schnorr_params(struct schnorr_Params *params);
void init_schnorr_keychain(struct schnorr_Keychain *keys);
void free_schnorr_keychain(struct schnorr_Keychain *keys);
void init_schnorr_signature(struct schnorr_Signature *signature);
void free_schnorr_signature(struct schnorr_Signature *signature);

#endif