#include <paishamir.h>

unsigned int paiShamir_distribution(struct paillier_Keychain *paikeys)
{
    unsigned int err = 0;
    int i = 0;

    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (paiShamir_distribution, paishamir)\n");
        return 0;
    }
    BIGNUM *c = BN_new();
    BIGNUM *ci = BN_new();
    BIGNUM *cN_prime = BN_new();
    BIGNUM *order = BN_new();
    BIGNUM *kappa_i[currentNumberOfDevices];
    BIGNUM *d[currentNumberOfDevices][G_POLYDEGREE];
    BIGNUM *xs[G_POLYDEGREE];
    BIGNUM *str_bn = BN_new();
    unsigned char *str_i = (char *)malloc(sizeof(char) * BUFFER);
    for (i = 0; i < currentNumberOfDevices; i++)
    {
        kappa_i[i] = BN_new();
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            d[i][j] = BN_new();
        }
    }
    for (i = 0; i < G_POLYDEGREE; i++)
    {
        xs[i] = BN_new();
    }

    err = EC_GROUP_get_order(g_globals.keychain->ec_group, order, ctx);
    if (err != 1)
    {
        printf(" * Failed to get the order of EC! (paiShamir_distribution, paishamir)\n");
        goto end;
    }

    for (i = 0; i < currentNumberOfDevices; i++)
    {
        err = rand_range(kappa_i[i], order);
        if (err != 1)
        {
            printf(" * Generation of random KAPPA_%d failed! (paiShamir_distribution, paishamir)\n", i);
            goto end;
        }

        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            err = rand_range(d[i][j], order);
            if (err != 1)
            {
                printf(" * Generation of random D_%d (I: %d) failed! (paiShamir_distribution, paishamir)\n", j, i);
                goto end;
            }
        }
    }

    // SHARE
    for (i = 0; i < currentNumberOfDevices; i++)
    {
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            sprintf(str_i, "%d", j);
            BN_dec2bn(&str_bn, str_i);
            err = BN_mod_exp(xs[j], g_ssaka_devicesKeys[i].pk, str_bn, order, ctx);
            if (err != 1)
            {
                printf(" * Computation of XS %d failed! (paiShamir_get_ci, paishamir)\n", j);
                goto end;
            }
        }
        
        err = paiShamir_get_ci(paikeys, kappa_i[(i + 1) % (currentNumberOfDevices)], d[(i + 1) % (currentNumberOfDevices)], xs, paikeys->pk->n_sq, cN_prime);
        if (err != 1)
        {
            printf(" * Get first CN' (%d) failed! (paiShamir_distribution, paishamir)\n", (i + 1) % (currentNumberOfDevices));
            goto end;
        }

        for (int j = 0; j < currentNumberOfDevices; j++)
        {
            if (j == i || j == (i + 1) % (currentNumberOfDevices))
                continue;
            err = paiShamir_get_ci(paikeys, kappa_i[j], d[j], xs, paikeys->pk->n_sq, ci);
            if (err != 1)
            {
                printf(" * Get C_%d failed! (paiShamir_distribution, paishamir)\n", j);
                goto end;
            }
            err = paiShamir_get_cN_prime(paikeys, cN_prime, ci, cN_prime);
            if (err != 1)
            {
                printf(" * Get CN' (%d) failed! (paiShamir_distribution, paishamir)\n", j);
                goto end;
            }
        }
        err = paiShamir_get_c(kappa_i[i], paikeys->pk->n, xs, d[i], c);
        if(err != 1)
        {
            printf(" * Compute C %d failed!", i);
            goto end;
        }
        err = paiShamir_get_share(paikeys, cN_prime, c, order, g_ssaka_devicesKeys[i].sk);
        if (err != 1)
        {
            printf(" * Get SHARE (%d) failed! (paiShamir_distribution, paishamir)\n", i);
            goto end;
        }
    }

end:
    BN_free(c);
    BN_free(ci);
    BN_free(order);
    BN_free(cN_prime);
    BN_free(str_bn);
    free(str_i);
    for (i = 0; i < currentNumberOfDevices; i++)
    {
        BN_free(kappa_i[i]);
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            BN_free(d[i][j]);
        }
    }
    for (i = 0; i < G_POLYDEGREE; i++)
    {
        BN_free(xs[i]);
    }
    BN_CTX_free(ctx);

    return err;
}

unsigned int paiShamir_get_ci(struct paillier_Keychain *paikeys, BIGNUM *kappa_i, BIGNUM *d[G_POLYDEGREE], BIGNUM *xs[G_POLYDEGREE], BIGNUM *mod, BIGNUM *ci)
{
    unsigned int err = 0;
    int i = 0;

    // POLYNOM CREATION
    BIGNUM *polynom[G_POLYDEGREE + 1];
    for (i; i <= G_POLYDEGREE; i++)
    {
        polynom[i] = BN_new();
    }
    BIGNUM *enc_x = BN_new();
    BIGNUM *precomp_message = BN_new();
    BIGNUM *precomp_noise = BN_new();

    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (paiShamir_get_ci, paishamir)\n");
        goto end;
    }

    // ENCRYPT X
    err = set_precomps(xs[1], precomp_message, precomp_noise);
    if (err != 1)
    {
        printf(" * Failed to set pre-computed values! (paiShamir_get_ci, paishamir)\n");
        goto end;
    }

    err = paillier_encrypt(paikeys->pk, xs[1], enc_x, precomp_message, precomp_noise);
    if (err != 1)
    {
        printf(" * Pailler encryption of POLYNOM %d failed! (paiShamir_get_ci, paishamir)\n", i);
        goto end;
    }

    // ENCRYPT KAPPA
    err = set_precomps(kappa_i, precomp_message, precomp_noise);
    if (err != 1)
    {
        printf(" * Failed to set pre-computed values! (paiShamir_get_ci, paishamir)\n");
        goto end;
    }

    err = paillier_encrypt(paikeys->pk, kappa_i, polynom[0], precomp_message, precomp_noise);
    if (err != 1)
    {
        printf(" * Pailler encryption of POLYNOM 0 failed! (paiShamir_get_ci, paishamir)\n");
        goto end;
    }

    for (i = 1; i <= G_POLYDEGREE; i++)
    {
        BN_copy(polynom[i], d[i - 1]);
        err = BN_mod_mul(polynom[i], polynom[i], xs[i-1], paikeys->pk->n_sq, ctx);
        if (err != 1)
        {
            printf(" * Multiplication of POLYNOM %d with XS %d failed! (paiShamir_get_ci, paishamir)\n", i, i);
            goto end;
        }
        err = homomorphy_mul_const(paikeys->pk, enc_x, polynom[i], polynom[i]);
        if (err != 1)
        {
            printf(" * Set the POLYNOM_%d failed! (paiShamir_get_ci, paishamir)\n", i);
            goto end;
        }
    }

    BN_dec2bn(&ci, "1");
    for (i = 0; i <= G_POLYDEGREE; i++)
    {
        err = homomorphy_add(paikeys->pk, polynom[i], ci, ci);
        if (err != 1)
        {
            printf(" * Computation of CI (%d) failed! (paiShamir_get_ci, paishamir)\n", i);
            goto end;
        }
    }

end:
    for (i = 0; i <= G_POLYDEGREE; i++)
    {
        BN_free(polynom[i]);
    }
    BN_free(precomp_message);
    BN_free(precomp_noise);
    BN_free(enc_x);
    BN_CTX_free(ctx);

    return err;
}

unsigned int paiShamir_get_cN_prime(struct paillier_Keychain *paikeys, BIGNUM *pre_cN, BIGNUM *cN, BIGNUM *cN_prime)
{
    return homomorphy_add(paikeys->pk, pre_cN, cN, cN_prime);
}

unsigned int paiShamir_get_c(BIGNUM *kappa, BIGNUM *mod, BIGNUM *xs[G_POLYDEGREE], BIGNUM *d[G_POLYDEGREE], BIGNUM *c)
{
    unsigned int err = 0;
    BIGNUM *tmp = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Generation of CTX failed! (paiShamir_get_c, paishamir)\n");
        goto end;
    }

    BN_copy(c, kappa);
    for(int i = 0; i < G_POLYDEGREE ; i++)
    {
        err = BN_mod_mul(tmp, xs[i], d[i], mod, ctx);
        if(err != 1)
        {
            printf(" * Failed to computer TMP (%d)! (paiShamir_get_c, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_mul(tmp, tmp, xs[1], mod, ctx);
        if(err != 1)
        {
            printf(" * Failed to computer TMP (%d)! (paiShamir_get_c, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_add(c, c, tmp, mod, ctx);
        if(err != 1)
        {
            printf(" * Failed to add ADD TMP to C (%d)! (paiShamir_get_c, paishamir)\n", i);
            goto end;
        }
    }

end:
    BN_free(tmp);
    BN_CTX_free(ctx);

    return err;
}

unsigned int paiShamir_get_share(struct paillier_Keychain *paikeys, BIGNUM *cN_prime, BIGNUM *c, BIGNUM *mod, BIGNUM *share)
{
    unsigned int err = 0;
    BIGNUM *enc = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (paiShamir_get_share, paishamir)\n");
        goto end;
    }

    err = paillier_decrypt(paikeys, cN_prime, share);
    if (err != 1)
    {
        printf(" * Paillier decryption failed! (paiShamir_get_share, paishamir)\n");
        goto end;
    }

    err = BN_mod_add(share, share, c, mod, ctx);
    if(err != 1)
    {
        printf(" * Failed to add C to SHARE! (paiShamir_get_share, paishamir)\n");
        goto end;
    }

end:
    BN_free(enc);
    BN_CTX_free(ctx);

    return err;
}

unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, BIGNUM *mod, BIGNUM *secret)
{
    unsigned int err = 0;
    if (size_of_list <= G_POLYDEGREE)
    {
        printf("There must be at least %d devices to reconstruct the secret!\n", G_POLYDEGREE + 1);
        return 0;
    }

    BN_dec2bn(&secret, "0");
    BIGNUM *sk_i = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (paiShamir_interpolation, paishamir)\n");
        goto end;
    }

    for (int i = 0; i < size_of_list; i++)
    {
        err = part_interpolation(devices_list, size_of_list, i, mod, sk_i);
        if (err != 1)
        {
            printf(" * Interpolation of PART %d failed! (paiShamir_interpolation, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_add(secret, secret, sk_i, mod, ctx);
        if (err != 1)
        {
            printf(" * Addition of PART %d to the SECRET failed! (paiShamir_interpolation, paishamir)\n", i);
            goto end;
        }
    }

end:
    BN_free(sk_i);
    BN_CTX_free(ctx);

    return err;
}

unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, BIGNUM *mod, BIGNUM *sk_i)
{
    unsigned int err = 0;
    BIGNUM *tmp_mul = BN_new();
    BIGNUM *sub = BN_new();
    BIGNUM *inv = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (part_interpolation, paishamir)\n");
        goto end;
    }

    BN_copy(sk_i, g_ssaka_devicesKeys[devices_list[current_device]].sk);
    for (int i = 0; i < size_of_list; i++)
    {
        if (current_device == i)
            continue;
        err = BN_mod_sub(sub, g_ssaka_devicesKeys[devices_list[i]].pk, g_ssaka_devicesKeys[devices_list[current_device]].pk, mod, ctx);
        if (err != 1)
        {
            printf(" * Computation of SUB (%d) failed! (part_interpolation, paishamir)\n", i);
            goto end;
        }
        if (!BN_mod_inverse(inv, sub, mod, ctx))
        {
            printf(" * Computation of INV (%d) failed! (part_interpolation, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_mul(tmp_mul, g_ssaka_devicesKeys[devices_list[i]].pk, inv, mod, ctx);
        if (err != 1)
        {
            printf(" * Computation of TMP_MUL (%d) failed! (part_interpolation, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_mul(sk_i, sk_i, tmp_mul, mod, ctx);
        if (err != 1)
        {
            printf(" * Computation of SK (%d) failed! (part_interpolation, paishamir)\n", i);
            goto end;
        }
    }

end:
    BN_free(tmp_mul);
    BN_free(sub);
    BN_free(inv);
    BN_CTX_free(ctx);
    return err;
}