#include <paillier_scheme.h>

unsigned int paillier_generate_keypair(struct paillier_Keychain *keychain)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Falied to generate CTX! (scheme 1, generate keypair)\n");
        return err;
    }

    err = gen_pqg_params(keychain->sk->p, keychain->sk->q, keychain->sk->lambda, keychain->pk);
    if(err != 1)
    {
        printf(" * Generate P, Q, G, params failed! (scheme 1, generate keypair)\n");
        goto end;
    }
    err = count_mi(keychain->sk->mi, keychain->pk->g, keychain->sk->lambda, keychain->pk->n_sq, keychain->pk->n);
    if(err != 1)
    {
        printf(" * Count MI failed! (scheme 1, generate keypair)\n");
        goto end;
    }

end:
    BN_CTX_free(ctx);
    return err;
}

unsigned int paillier_encrypt(struct paillier_PublicKey *pk, BIGNUM *plain, BIGNUM *cipher, BIGNUM *precomp_message, BIGNUM *precomp_noise)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Falied to generate CTX! (scheme 1, encrypt)\n");
        return err;
    }

    BIGNUM *tmp_rnd = BN_new();

    if (BN_cmp(plain, pk->n) != -1)
    {
        printf(" * Plaintext is bigger then the length of N! (scheme 1, encrypt)\n");
        goto end;
    }

    if (BN_is_zero(precomp_message) == 1)
    {
        err = BN_mod_exp(precomp_message, pk->g, plain, pk->n_sq, ctx);
        if(err != 1)
        {
            printf(" * Message mod_exp operation falied! (scheme 1, encrypt)\n");
            goto end;
        }
    }
    
    if (BN_is_zero(precomp_noise) == 1)
    {
        err = generate_rnd_paillier(pk->n, pk->n, tmp_rnd);
        if(err != 1)
        {
            printf(" * Generate random falied! (scheme 1, encrypt)\n");
            goto end;
        }
        err = BN_mod_exp(precomp_noise, tmp_rnd, pk->n, pk->n_sq, ctx);
        if(err != 1)
        {
            printf(" * Noise mod_exp operation falied! (scheme 1, encrypt)\n");
            goto end;
        }
    }

    err = BN_mod_mul(cipher, precomp_message, precomp_noise, pk->n_sq, ctx);
    if(err != 1)
    {
        printf(" * Multiplication of message and noise falied! (scheme 1, encrypt)\n");
        goto end;
    }

end:
    BN_free(tmp_rnd);
    BN_CTX_free(ctx);

    return err;
}

unsigned int paillier_decrypt(struct paillier_Keychain *keychain, BIGNUM *cipher, BIGNUM *plain)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Falied to generate CTX! (scheme 1, decrypt)\n");
        return err;
    }

    BIGNUM *u = BN_new();

    err = BN_mod_exp(u, cipher, keychain->sk->lambda, keychain->pk->n_sq, ctx);
    if(err != 1)
    {
        printf(" * Cipher mod_exp operation failed! (scheme 1, decrypt)\n");
        goto end;
    }
    err = L(u, keychain->pk->n, u, ctx);
    if(err != 1)
    {
        printf(" * L function failed! (scheme 1, decrypt)\n");
        goto end;
    }
    err = BN_mod_mul(plain, u, keychain->sk->mi, keychain->pk->n, ctx);
    if(err != 1)
    {
        printf(" * Cipher mod_mul operation failed! (scheme 1, decrypt)\n");
        goto end;
    }

end:
    BN_free(u);
    BN_CTX_free(ctx);

    return err;
}

void init_paillier_keychain(struct paillier_Keychain *keychain)
{
    keychain->pk = (struct paillier_PublicKey *)malloc(sizeof(struct paillier_PublicKey));
    keychain->pk->g = BN_new();
    keychain->pk->n = BN_new();
    keychain->pk->n_sq = BN_new();
    keychain->sk = (struct paillier_PrivateKey *)malloc(sizeof(struct paillier_PrivateKey));
    keychain->sk->lambda = BN_new();
    keychain->sk->mi = BN_new();
    keychain->sk->p = BN_new();
    keychain->sk->q = BN_new();

    return;
}

void free_paillier_keychain(struct paillier_Keychain *keychain)
{
    BN_free(keychain->pk->g);
    BN_free(keychain->pk->n);
    BN_free(keychain->pk->n_sq);
    free(keychain->pk);
    BN_free(keychain->sk->lambda);
    BN_free(keychain->sk->mi);
    BN_free(keychain->sk->p);
    BN_free(keychain->sk->q);
    free(keychain->sk);

    return;
}

////////////////////////////////////////////////////////
// HOMOMORPHY FUNCTIONS ////////////////////////////////
////////////////////////////////////////////////////////

unsigned int homomorphy_add(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *b, BIGNUM *res)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;
    // Add one encrypted unsigned long longeger to another
    unsigned int err = BN_mod_mul(res, a, b, pk->n_sq, ctx);

    BN_CTX_free(ctx);
    return err;
}

unsigned int homomorphy_add_const(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;
    // Add constant n to an encrypted unsigned long longeger
    unsigned int err = 0;
    BIGNUM *p_1 = BN_new();
    err += BN_mod_exp(p_1, pk->g, n, pk->n_sq, ctx);
    err += BN_mod_mul(res, a, p_1, pk->n_sq, ctx);

    BN_free(p_1);
    BN_CTX_free(ctx);
    if (err != 2)
        return 0;
    return 1;
}

unsigned int homomorphy_mul_const(struct paillier_PublicKey *pk, BIGNUM *a, BIGNUM *n, BIGNUM *res)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;
    // Multiplies an encrypted unsigned long longeger by a constant
    unsigned int err = BN_mod_exp(res, a, n, pk->n_sq, ctx);

    BN_CTX_free(ctx);
    return err;
}