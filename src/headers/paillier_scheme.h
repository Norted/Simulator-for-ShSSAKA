#ifndef __SCHEME3_H__
#define __SCHEME3_H__

#include <support_functions.h>
#include <globals.h>

unsigned int paillier_generate_keypair(struct paillier_Keychain *keychain);
unsigned int paillier_encrypt(struct paillier_PublicKey *pk, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise);
unsigned int paillier_decrypt(struct paillier_Keychain *keychain, BIGNUM *cipher, BIGNUM *plain);

void init_paillier_keychain(struct paillier_Keychain *keychain);
void free_paillier_keychain(struct paillier_Keychain *keychain);

unsigned int homomorphy_add(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *b, BIGNUM *res);
unsigned int homomorphy_add_const(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);
unsigned int homomorphy_mul_const(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res);

#endif