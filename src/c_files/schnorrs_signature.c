#include <schnorrs_signature.h>

DSA *dsa;

unsigned int gen_schnorr_params(struct SchnorrParams *params) {
    dsa = DSA_new();
    return bn_gen_params(dsa, params->p, params->q, params->g);
}

unsigned int gen_schnorr_keys(struct SchnorrKeychain *keys) {
    return bn_gen_keys(dsa, keys->sk, keys->pk);
}

unsigned int schnorr_sign(struct SchnorrParams *params, unsigned char *sk, unsigned char *message, unsigned char *kappa, struct SchnorrSignature *signature) {
    unsigned int err = 0;
    unsigned char c[BUFFER];
    if(strlen(signature->r) == 0) {
        err += random_str_num_in_range(signature->r, atoi(params->q), 1);
    }

    err += bn_modexp(params->g, signature->r, params->p, c);

    if(strcmp(kappa, "0") != 0) {
        err += bn_modexp(signature->c_prime, signature->r, params->p, kappa);
    }

    err += hash(signature->hash, message, c, kappa);
    
    unsigned char mul[BUFFER];
    err += bn_modmul(sk, signature->hash, params->q, mul);
    err += bn_modsub(signature->r, mul, params->q, signature->signature); // modsub -> modadd

    if(err < 4)
        return 0;
    return 1;
}

unsigned int schnorr_verify(struct SchnorrParams *params, unsigned char *pk, unsigned char *message, unsigned char *kappa, struct SchnorrSignature *signature) {
    unsigned int err = 0;
    unsigned char c_prime_1[BUFFER];
    unsigned char c_prime_2[BUFFER];
    unsigned char hash_prime[BUFFER];
    //unsigned char pk_inv[BUFFER];
    //err += bn_modinverse(pk, params->p, pk_inv);

    err += bn_modexp(params->g, signature->signature, params->p, c_prime_1);
    err += bn_modexp(pk, signature->hash, params->p, c_prime_2); // pk -> pk_inv
    err += bn_modmul(c_prime_1, c_prime_2, params->p, signature->c_prime);

    if(strcmp(kappa, "0") != 0) {
        err += bn_modexp(signature->c_prime, signature->r, params->p, kappa);
    }

    err += hash(hash_prime, message, signature->c_prime, kappa);

    //printf("|--> 1. %s\n|--> 2. %s\n", signature->hash, hash_prime);
    if(err >= 4 && bn_cmp(signature->hash, hash_prime) == 0) // err >= 5 && bn_cmp(signature->hash, hash_prime) == 0
        return 1;
    return 0;
}

void free_schnorr_mem() {
    DSA_free(dsa);
    
    return;
}