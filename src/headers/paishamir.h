#ifndef __PAISHAMIR_H__
#define __PAISHAMIR_H__

#include <globals.h>
#include <paillier.h>
#include <SSAKA.h>

unsigned int _shamir_distribution(unsigned char *secret);
unsigned int paiShamir_distribution(struct paillierKeychain *paikeys);
unsigned int paiShamir_get_ci(struct paillierKeychain *paikeys, unsigned char *kappa_i, unsigned char d[G_POLYDEGREE][BUFFER], unsigned char *x, unsigned char *ci);
unsigned int paiShamir_get_cN_prime(struct paillierKeychain *paikeys, unsigned char *pre_cN, unsigned char *cN, unsigned char *cN_prime);
unsigned int paiShamir_get_share(struct paillierKeychain *paikeys, unsigned char *cN_prime, unsigned char *c, unsigned char *share);
unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned char *secret);
unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, unsigned char *sk_i);

#endif