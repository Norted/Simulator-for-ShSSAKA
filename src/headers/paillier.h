#ifndef __PAILLIER_H__
#define __PAILLIER_H__

#include <globals.h>
#include <cjson/cJSON.h>

unsigned int generate_keypair(struct paillierKeychain *keyring);
unsigned int encrypt(struct paillierPublicKey pk, unsigned char *plain, unsigned char *cipher, unsigned char *precomp_message, unsigned char *precomp_noise);
unsigned int decrypt(struct paillierKeychain *keyring, unsigned char *cipher, unsigned char *plain);
unsigned int add(struct paillierPublicKey pk, unsigned char *a, unsigned char *b, unsigned char *res);
unsigned int add_const(struct paillierPublicKey pk, unsigned char *a, unsigned char *n, unsigned char *res);
unsigned int mul_const(struct paillierPublicKey pk, unsigned char *a, unsigned char *n, unsigned char *res);
unsigned int test_homomorphic();

#endif