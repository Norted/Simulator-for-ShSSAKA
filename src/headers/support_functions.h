#ifndef __OPENSSL_BN_H__
#define __OPENSSL_BN_H__

#include <globals.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *lambda, struct paillier_PublicKey *pk);
unsigned int gen_DSA_params(BIGNUM *p, BIGNUM *q, BIGNUM *g);
unsigned int lcm(BIGNUM *a, BIGNUM *b, BIGNUM *res);
unsigned int count_mi(BIGNUM *mi, BIGNUM *g, BIGNUM *lambda, BIGNUM *n_sq, BIGNUM *n);
unsigned int L(BIGNUM *u, BIGNUM *n, BIGNUM *res, BN_CTX *ctx);
unsigned int l_or_a_computation(BIGNUM *p, BIGNUM *q, BIGNUM *lambda);
unsigned int generate_rnd(BIGNUM *range, BIGNUM *gcd_chck, BIGNUM *random, unsigned int strength);
unsigned int hash(BIGNUM *res, BIGNUM *Y, BIGNUM *t_s, BIGNUM *kappa);
unsigned int chinese_remainder_theorem(BIGNUM *num[], BIGNUM *rem[], int size, BIGNUM *result);
void init_keychain(struct paillier_Keychain *keychain);
void free_keychain(struct paillier_Keychain *keychain);
cJSON *parse_JSON(const char *restrict file_name);
unsigned int find_value(cJSON *json, BIGNUM *search, BIGNUM *result);
int save_keys(const char *restrict file_name, struct paillier_Keychain *keychain);
void read_keys(const char *restrict file_name, struct paillier_Keychain *keychain);
int precomputation(const char *restrict file_name, struct paillier_Keychain *keychain, unsigned int range, unsigned int type);// type: 1 ... message, 2 ... noise
cJSON *message_precomp(BIGNUM *range, BIGNUM *base, BIGNUM *mod);
cJSON *noise_precomp(BIGNUM *range, BIGNUM *exp_value, BIGNUM *mod);

#endif