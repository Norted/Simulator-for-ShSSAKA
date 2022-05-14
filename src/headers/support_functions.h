#ifndef __OPENSSL_BN_H__
#define __OPENSSL_BN_H__

#include <schnorrs_signature.h>
#include <ShSSAKA.h>
#include <globals.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *lambda, struct paillier_PublicKey *pk);
unsigned int lcm(BIGNUM *a, BIGNUM *b, BIGNUM *res);
unsigned int count_mi(BIGNUM *mi, BIGNUM *g, BIGNUM *lambda, BIGNUM *n_sq, BIGNUM *n);
unsigned int L(BIGNUM *u, BIGNUM *n, BIGNUM *res);
unsigned int lambda_computation(BIGNUM *p, BIGNUM *q, BIGNUM *lambda);
unsigned int generate_rnd_paillier(BIGNUM *bn_range, BIGNUM *gcd_chck, BIGNUM *random);
unsigned int ec_hash(const EC_GROUP *group, BIGNUM *res, BIGNUM *Y, EC_POINT *t_s, EC_POINT *kappa);
unsigned int rand_range(BIGNUM * rnd, const BIGNUM * bn_range);
unsigned int rand_point(const EC_GROUP *group, EC_POINT *point);
unsigned int set_precomps(BIGNUM *message, BIGNUM *pre_message, BIGNUM *pre_noise);

void init_serversign(const EC_GROUP *group, struct ServerSign *server_sign);
void free_serversign(struct ServerSign *server_sign);
void init_clientproof(const EC_GROUP *group, struct ClientProof *client_proof);
void free_clientproof(struct ClientProof *client_proof);
void init_deviceproof(const EC_GROUP *group, struct DeviceProof *device_proof);
void free_deviceproof(struct DeviceProof *device_proof);

void *thread_creation(void *threadid);
unsigned int threaded_precomputation();

cJSON *parse_JSON(const char *restrict file_name);
unsigned int find_value(cJSON *json, BIGNUM *search, BIGNUM *result);
void read_keys(const char *restrict file_name, struct paillier_Keychain *keychain);
int write_keys(const char *restrict file_name, struct paillier_Keychain *keychain);

int precomputation(const char *restrict file_name, struct paillier_Keychain *keychain, unsigned int int_range, unsigned int type); // type: 1 ... message, 2 ... noise
cJSON *message_precomp(unsigned int int_range, BIGNUM *base, BIGNUM *mod);
cJSON *noise_precomp(unsigned int int_range, BIGNUM *exp_value, BIGNUM *mod);

#endif