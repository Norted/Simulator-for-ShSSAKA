#include <schnorrs_signature.h>

unsigned int gen_schnorr_params(EC_GROUP *group, struct schnorr_Keychain *keychain)
{
    unsigned int err = 0;

    keychain->keys = EC_KEY_new_by_curve_name(NID_secp256k1);
    keychain->ec_group = group;
    err = EC_KEY_set_group(keychain->keys, keychain->ec_group);
    if (err != 1)
    {
        printf(" * Failed to set GROUP of the keys! (gen_ec_schnorr_params, schnorrs_signature_ec)\n");
        goto end;
    }
    err = EC_KEY_generate_key(keychain->keys);
    if (err != 1)
    {
        printf(" * Failed to generate KEYS! (gen_ec_schnorr_params, schnorrs_signature_ec)\n");
        goto end;
    }

end:
    return err;
}

unsigned int schnorr_sign(struct schnorr_Keychain *params, BIGNUM *sk, BIGNUM *message, EC_POINT *kappa, struct schnorr_Signature *signature)
{
    unsigned int err = 0;

    EC_POINT *C = EC_POINT_new(params->ec_group);
    BIGNUM *mul = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (schnorrs_signature, ec_schnorr_sign)\n");
        goto end;
    }

    if (BN_is_zero(signature->r) == 1)
    {
        err = rand_range(signature->r, EC_GROUP_get0_order(params->ec_group));
        if (err != 1)
        {
            printf(" * Failed to generate random signature R! (schnorrs_signature, ec_schnorr_sign)\n");
            goto end;
        }
    }

    err = EC_POINT_mul(params->ec_group, C, signature->r, NULL, NULL, ctx);
    if (err != 1)
    {
        printf(" * Computation G^R mod P failed! (schnorrs_signature, ec_schnorr_sign)\n");
        goto end;
    }

    if (EC_POINT_is_at_infinity(params->ec_group, kappa) != 1)
    {
        err = EC_POINTs_mul(params->ec_group, kappa, NULL, 1, &signature->c_prime, &signature->r, ctx);
        if (err != 1)
        {
            printf(" * Computation of KAPPA failed! (schnorrs_signature, ec_schnorr_sign)\n");
            goto end;
        }
    }

    err = ec_hash(params->ec_group, signature->hash, message, C, kappa);
    if (err != 1)
    {
        printf(" * Hash compuatation failed! (schnorrs_signature, ec_schnorr_sign)\n");
        goto end;
    }

    err = BN_mod_mul(mul, sk, signature->hash, EC_GROUP_get0_order(params->ec_group), ctx);
    if (err != 1)
    {
        printf(" * Multiplication of SK with HASH failed! (schnorrs_signature, ec_schnorr_sign)\n");
        goto end;
    }
    err = BN_mod_sub(signature->signature, signature->r, mul, EC_GROUP_get0_order(params->ec_group), ctx); // modsub -> modadd
    if (err != 1)
    {
        printf(" * Signature computation failed! (schnorrs_signature, ec_schnorr_sign)\n");
        goto end;
    }

end:
    // BN_free(c);
    EC_POINT_free(C);
    BN_free(mul);
    BN_CTX_free(ctx);

    return err;
}

unsigned int ec_schnorr_verify(struct schnorr_Keychain *params, EC_POINT *pk, BIGNUM *message, EC_POINT *kappa, struct schnorr_Signature *signature)
{
    unsigned int err = 0;
    EC_POINT *C_P1 = EC_POINT_new(params->ec_group);
    EC_POINT *C_P2 = EC_POINT_new(params->ec_group);
    BIGNUM *hash_prime = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (schnorrs_signature, ec_schnorr_verify)\n");
        goto end;
    }

    err = EC_POINT_mul(params->ec_group, C_P1, signature->signature, NULL, NULL, ctx);
    if (err != 1)
    {
        printf(" * Computaion of G^signature mod P failed! (schnorrs_signature, ec_schnorr_verify)\n");
        goto end;
    }
    err = EC_POINTs_mul(params->ec_group, C_P2, NULL, 1, &pk, &signature->hash, ctx);
    if (err != 1)
    {
        printf(" * Computation of PK^hash mod P failed! (schnorrs_signature, ec_schnorr_verify)\n");
        goto end;
    }
    err = EC_POINT_add(params->ec_group, signature->c_prime, C_P1, C_P2, ctx);
    if (err != 1)
    {
        printf(" * Computation of C_PRIME failed! (schnorrs_signature, ec_schnorr_verify)\n");
        goto end;
    }

    if (EC_POINT_is_at_infinity(params->ec_group, kappa) != 1)
    {
        err = EC_POINTs_mul(params->ec_group, kappa, NULL, 1, &signature->c_prime, &signature->r, ctx);
        if (err != 1)
        {
            printf(" * Computation of KAPPA failed! (schnorrs_signature, ec_schnorr_verify)\n");
            goto end;
        }
    }

    err = ec_hash(params->ec_group, hash_prime, message, signature->c_prime, kappa);
    if (err != 1)
    {
        printf(" * Hash computation failed! (schnorrs_signatire, ec_schnorr_verify)\n");
        goto end;
    }

    if (BN_cmp(signature->hash, hash_prime) != 0)
    {
        printf(" * Hashes does not match! (schnorrs_signature, ec_schnorr_verify)\n\t>> H1: %s\n\t>> H2: %s\n",
               BN_bn2dec(signature->hash), BN_bn2dec(hash_prime));
        err = 0;
        goto end;
    }

end:
    EC_POINT_free(C_P1);
    EC_POINT_free(C_P2);
    BN_free(hash_prime);
    BN_CTX_free(ctx);

    return err;
}

void free_schnorr_keychain(struct schnorr_Keychain *keychain)
{
    EC_GROUP_free(keychain->ec_group);
    EC_KEY_free(keychain->keys);

    return;
}

void init_schnorr_signature(EC_GROUP *group, struct schnorr_Signature *signature)
{
    signature->c_prime = EC_POINT_new(group);
    signature->hash = BN_new();
    signature->r = BN_new();
    signature->signature = BN_new();

    return;
}

void free_schnorr_signature(struct schnorr_Signature *signature)
{
    EC_POINT_free(signature->c_prime);
    BN_free(signature->hash);
    BN_free(signature->r);
    BN_free(signature->signature);

    return;
}