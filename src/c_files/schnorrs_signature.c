#include <schnorrs_signature.h>

unsigned int gen_schnorr_params(DSA *dsa, struct schnorr_Params *params)
{    
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_q = BN_new();
    BIGNUM *bn_g = BN_new();

    unsigned int err = DSA_generate_parameters_ex(dsa, BUFFER, NULL, 0, NULL, NULL, NULL);
    DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);

    if(err != 0) {
        BN_copy(params->p, bn_p);
        BN_copy(params->q, bn_q);
        BN_copy(params->g, bn_g);
    }

    return err;
    //return gen_DSA(1, params, 0, NULL);
}

unsigned int gen_schnorr_keys(DSA *dsa, struct schnorr_Keychain *keys)
{
    BIGNUM *bn_sk = BN_new();
    BIGNUM *bn_pk = BN_new();

    unsigned int err = DSA_generate_key(dsa);
    DSA_get0_key(dsa, &bn_pk, &bn_sk);

    if(err != 0) {
        BN_copy(keys->sk, bn_sk);
        BN_copy(keys->pk, bn_pk);
    }

end:
    return err;
    //return gen_DSA(0, NULL, 1, keys);
}

unsigned int schnorr_sign(struct schnorr_Params *params, BIGNUM *sk, BIGNUM *message, BIGNUM *kappa, struct schnorr_Signature *signature)
{
    unsigned int err = 0;

    BIGNUM *c = BN_new();
    BIGNUM *mul = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (schnorrs_signature, schnorr_sign)\n");
        goto end;
    }

    if (BN_is_zero(signature->r) == 1)
    {
        err = rand_range(signature->r, params->q);
        if (err != 1)
        {            
            printf(" * Failed to generate random signature R! (schnorrs_signature, schnorr_sign)\n");
            goto end;
        }
    }

    err = BN_mod_exp(c, params->g, signature->r, params->p, ctx);
    if (err != 1)
    {
        printf(" * Computation G^R mod P failed! (schnorrs_signature, schnorr_sign)\n");
        goto end;
    }

    if (BN_is_zero(kappa) != 1)
    {
        err = BN_mod_exp(kappa, signature->c_prime, signature->r, params->p, ctx);
        if (err != 1)
        {
            printf(" * Computation of KAPPA failed! (schnorrs_signature, schnorr_sign)\n");
            goto end;
        }
    }

    err = hash(signature->hash, message, c, kappa);
    if (err != 1)
    {
        printf(" * Hash compuatation failed! (schnorrs_signature, schnorr_sign)\n");
        goto end;
    }
    printf(">> first S_H: %s\n", BN_bn2dec(signature->hash));

    err = BN_mod_mul(mul, sk, signature->hash, params->q, ctx);
    if (err != 1)
    {
        printf(" * Multiplication of SK with HASH failed! (schnorrs_signature, schnorr_sign)\n");
        goto end;
    }
    err = BN_mod_sub(signature->signature, signature->r, mul, params->q, ctx); // modsub -> modadd
    if (err != 1)
    {
        printf(" * Signature computation failed! (schnorrs_signature, schnorr_sign)\n");
        goto end;
    }

end:
    BN_free(c);
    BN_free(mul);
    BN_CTX_free(ctx);

    return err;
}

unsigned int schnorr_verify(struct schnorr_Params *params, BIGNUM *pk, BIGNUM *message, BIGNUM *kappa, struct schnorr_Signature *signature)
{
    unsigned int err = 0;
    BIGNUM *c_prime_1 = BN_new();
    BIGNUM *c_prime_2 = BN_new();
    BIGNUM *hash_prime = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (schnorrs_signature, schnorr_verify)\n");
        goto end;
    }

    err = BN_mod_exp(c_prime_1, params->g, signature->signature, params->p, ctx);
    if (err != 1)
    {
        printf(" * Computaion of G^signature mod P failed! (schnorrs_signature, schnorr_verify)\n");
        goto end;
    }
    err = BN_mod_exp(c_prime_2, pk, signature->hash, params->p, ctx);
    if (err != 1)
    {
        printf(" * Computation of PK^hash mod P failed! (schnorrs_signature, schnorr_verify)\n");
        goto end;
    }
    err = BN_mod_mul(signature->c_prime, c_prime_1, c_prime_2, params->p, ctx);
    if (err != 1)
    {
        printf(" * Computation of C_PRIME failed! (schnorrs_signature, schnorr_verify)\n");
        goto end;
    }

    if (BN_is_zero(kappa) != 1)
    {
        err = BN_mod_exp(kappa, signature->c_prime, signature->r, params->p, ctx);
        if (err != 1)
        {
            printf(" * Computation of KAPPA failed! (schnorrs_signature, schnorr_verify)\n");
            goto end;
        }
    }

    err = hash(hash_prime, message, signature->c_prime, kappa);
    if (err != 1)
    {
        printf(" * Hash computation failed! (schnorrs_signatire, schnorr_verify)\n");
        goto end;
    }

    printf(">> S_H: %s\n>> H_P: %s\n", BN_bn2dec(signature->hash),BN_bn2dec(hash_prime));

    if(BN_cmp(signature->hash, hash_prime) != 0)
    {
        printf(" * Hashes does not match! (schnorrs_signature, schnorr_verify)\n");
        err = 0;
        goto end;
    }

end:
    BN_free(c_prime_1);
    BN_free(c_prime_2);
    BN_free(hash_prime);
    BN_CTX_free(ctx);

    return err;
}

void init_schnorr_params(struct schnorr_Params *params)
{
    params->g = BN_new();
    params->p = BN_new();
    params->q = BN_new();

    return;
}

void free_schnorr_params(struct schnorr_Params *params)
{
    BN_free(params->g);
    BN_free(params->p);
    BN_free(params->q);
    
    return;
}

void init_schnorr_keychain(struct schnorr_Keychain *keys)
{
    keys->pk = BN_new();
    keys->sk = BN_new();
    
    return;
}

void free_schnorr_keychain(struct schnorr_Keychain *keys)
{
    BN_free(keys->pk);
    BN_free(keys->sk);
    
    return;
}

void init_schnorr_signature(struct schnorr_Signature *signature)
{
    signature->c_prime = BN_new();
    signature->hash = BN_new();
    signature->r = BN_new();
    signature->signature = BN_new();

    return;
}

void free_schnorr_signature(struct schnorr_Signature *signature)
{
    BN_free(signature->c_prime);
    BN_free(signature->hash);
    BN_free(signature->r);
    BN_free(signature->signature);

    return;
}

void init_DSA(DSA *dsa)
{
    dsa = DSA_new();
    return;
}

void free_DSA(DSA *dsa)
{
    DSA_free(dsa);
    return;
}