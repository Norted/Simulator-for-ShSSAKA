#ifndef __PAISHAMIR_H__
#define __PAISHAMIR_H__

#include <paillier_scheme.h>
#include <support_functions.h>
#include <globals.h>

unsigned int paiShamir_distribution(struct paillier_Keychain *paikeys);
unsigned int paiShamir_get_ci(struct paillier_Keychain *paikeys, BIGNUM *kappa_i, BIGNUM *d[G_POLYDEGREE], BIGNUM *xs[G_POLYDEGREE], BIGNUM *mod, BIGNUM *ci);
unsigned int paiShamir_get_cN_prime(struct paillier_Keychain *paikeys, BIGNUM *pre_cN, BIGNUM *cN, BIGNUM *cN_prime);
unsigned int paiShamir_get_c(BIGNUM *kappa, BIGNUM *mod, BIGNUM *xs[G_POLYDEGREE], BIGNUM *d[G_POLYDEGREE], BIGNUM *c);
unsigned int paiShamir_get_share(struct paillier_Keychain *paikeys, BIGNUM *cN_prime, BIGNUM *c, BIGNUM *mod, BIGNUM *share);
unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, BIGNUM *mod, BIGNUM *secret);
unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, BIGNUM *mod, BIGNUM *sk_i);

#endif