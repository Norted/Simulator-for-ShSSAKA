#include <paishamir.h>

unsigned int paiShamir_distribution(struct paillier_Keychain *paikeys) {
    unsigned int err = 0;
    int i = 0;

    BIGNUM *c = BN_new();
    BIGNUM *ci = BN_new();
    BIGNUM *cN_prime = BN_new();
    BIGNUM *kappa_i[currentNumberOfDevices];
    BIGNUM *d[currentNumberOfDevices][G_POLYDEGREE];

    for (i; i < currentNumberOfDevices; i++)
    {
        kappa_i[i] = BN_new();
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            d[i][j] = BN_new();
        }
    }

    for (i = 0; i < currentNumberOfDevices; i++) {
        err = rand_range(kappa_i[i], paikeys->sk->q);
        if(err != 1)
        {
            printf(" * Generation of random KAPPA_%d failed! (paiShamir_distribution, paishamir)\n", i);
            goto end;
        }

        for(int j = 0; j < G_POLYDEGREE; j++) {
            err = rand_range(d[i][j], paikeys->sk->q);
            if(err != 1)
            {
                printf(" * Generation of random D_%d (I: %d) failed! (paiShamir_distribution, paishamir)\n", j,i);
                goto end;
            }
        }
    }
    
    // SHARE
    for (i = 0; i < currentNumberOfDevices; i++) {
        err = paiShamir_get_ci(paikeys, kappa_i[i], d[i], g_ssaka_devicesKeys[i].pk, c);
        if(err != 1)
        {
            printf(" * Get first C_%d failed! (paiShamir_distribution, paishamir)\n", i);
            goto end;
        }
        err = paiShamir_get_ci(paikeys, kappa_i[(i+1)%(currentNumberOfDevices)], d[(i+1)%(currentNumberOfDevices)], g_ssaka_devicesKeys[i].pk, cN_prime);
        if(err != 1)
        {
            printf(" * Get first CN' (%d) failed! (paiShamir_distribution, paishamir)\n", (i+1)%(currentNumberOfDevices));
            goto end;
        }

        for (int j = 0; j < currentNumberOfDevices; j++) {
            if(j == i || j == (i+1)%(currentNumberOfDevices))
                continue;
            err = paiShamir_get_ci(paikeys, kappa_i[j], d[j], g_ssaka_devicesKeys[i].pk, ci);
            if(err != 1)
            {
                printf(" * Get C_%d failed! (paiShamir_distribution, paishamir)\n", j);
                goto end;
            }
            err = paiShamir_get_cN_prime(paikeys, cN_prime, ci, cN_prime);
            if(err != 1)
            {
                printf(" * Get CN' (%d) failed! (paiShamir_distribution, paishamir)\n", j);
                goto end;
            }
        }
        err = paiShamir_get_share(paikeys, cN_prime, c, g_ssaka_devicesKeys[i].sk);
        if(err != 1)
        {
            printf(" * Get SHARE (%d) failed! (paiShamir_distribution, paishamir)\n", i);
            goto end;
        }
    }

end:
    BN_free(c);
    BN_free(ci);
    BN_free(cN_prime);
    for (i = 0; i < currentNumberOfDevices; i++)
    {
        BN_free(kappa_i[i]);
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            BN_free(d[i][j]);
        }
    }

    return err;
}

unsigned int paiShamir_get_ci(struct paillier_Keychain *paikeys, BIGNUM *kappa_i, BIGNUM *d[G_POLYDEGREE], BIGNUM *x, BIGNUM *ci) {
    unsigned int err = 0;
    int i = 0;

    // POLYNOM CREATION
    BIGNUM *polynom[G_POLYDEGREE+1];
    BIGNUM *xs[G_POLYDEGREE+1];
    for (i; i <=G_POLYDEGREE; i++)
    {
        polynom[i] = BN_new();
        xs[i] = BN_new();
    }
    unsigned char *str_i = (char*)malloc(sizeof(char) * BUFFER);
    BIGNUM *str_bn = BN_new();
    BIGNUM *ci_tmp = BN_new();
    BIGNUM *tmp_r = BN_new();
    BIGNUM *precomp_message = BN_new();
    BIGNUM *precomp_noise = BN_new();
    if(pre_message == 1)
    {
        BN_dec2bn(&precomp_message, "0");
    }
    else
    {
        err = find_value(json_message, kappa_i, precomp_message);
    }

    if(pre_noise == 1)
    {
        BN_dec2bn(&precomp_noise, "0");
    }
    else
    {
        err = rand_range(tmp_r, range);
        err = find_value(json_noise, tmp_r, precomp_message);
    }

    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (paiShamir_get_ci, paishamir)\n");
        goto end;
    }

    err = paillier_encrypt(paikeys->pk, kappa_i, polynom[0], precomp_message, precomp_noise);
    if(err != 1)
    {
        printf(" * Pailler encryption of POLYNOM 0 failed! (paiShamir_get_ci, paishamir)\n");
        goto end;
    }

    for (i = 1; i <= G_POLYDEGREE; i++) {
        if(pre_message == 0)
        {
            BN_dec2bn(&precomp_message, "0");
        }
        else
        {
            err = find_value(json_message, kappa_i, precomp_message);
        }
        
        if(pre_noise == 0)
        {
            BN_dec2bn(&precomp_noise, "0");
        }
        else
        {
            err = rand_range(tmp_r, range);
            err = find_value(json_noise, tmp_r, precomp_message);
        }

        err = paillier_encrypt(paikeys->pk, d[i-1], polynom[i], precomp_message, precomp_noise);
        if(err != 1)
        {
            printf(" * Pailler encryption of POLYNOM %d failed! (paiShamir_get_ci, paishamir)\n", i);
            goto end;
        }
    }

    for (i = 0; i <= G_POLYDEGREE; i++) {
        sprintf(str_i, "%d", i);
        BN_dec2bn(&str_bn, str_i);
        err = BN_mod_exp(xs[i], x, str_bn, paikeys->pk->n, ctx);
        if(err != 1)
        {
            printf(" * Computation of XS %d failed! (paiShamir_get_ci, paishamir)\n", i);
            goto end;
        }
    }

    BN_dec2bn(&ci, "1");
    for(i = 0; i <= G_POLYDEGREE; i++) {
        err = homomorphy_mul_const(paikeys->pk, polynom[i], xs[i], ci_tmp);
        if(err != 1)
        {
            printf(" * Computation of CI_TMP (%d) failed! (paiShamir_get_ci, paishamir)\n", i);
            goto end;
        }
        err = homomorphy_add(paikeys->pk, ci, ci_tmp, ci);
        if(err != 1)
        {
            printf(" * Computation of CI (%d) failed! (paiShamir_get_ci, paishamir)\n", i);
            goto end;
        }
    }

end:
    for (i = 0; i <=G_POLYDEGREE; i++)
    {
        BN_free(polynom[i]);
        BN_free(xs[i]);
    }

    free(str_i);
    BN_free(str_bn);
    BN_free(ci_tmp);
    BN_free(tmp_r);
    BN_free(precomp_message);
    BN_free(precomp_noise);
    BN_CTX_free(ctx);
    
    return err;
}

unsigned int paiShamir_get_cN_prime(struct paillier_Keychain *paikeys, BIGNUM *pre_cN, BIGNUM *cN, BIGNUM *cN_prime) {
    return homomorphy_add(paikeys->pk, pre_cN, cN, cN_prime);
}

unsigned int paiShamir_get_share(struct paillier_Keychain *paikeys, BIGNUM *cN_prime, BIGNUM *c, BIGNUM *share) {
    unsigned int err = 0;
    BIGNUM *enc = BN_new();
    err = homomorphy_add(paikeys->pk, c, cN_prime, enc);
    if(err != 1)
    {
        printf(" * Addition failed! (paiShamir_get_share, paishamir)\n");
        goto end;
    }
    err = paillier_decrypt(paikeys, enc, share);
    if(err != 1)
    {
        printf(" * Paillier decryption failed! (paiShamir_get_share, paishamir)\n");
        goto end;
    }

end:
    BN_free(enc);
    
    return err;
}

unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, BIGNUM *q, BIGNUM *secret) {
    unsigned int err = 0;
    if(size_of_list <= G_POLYDEGREE) {
        printf("There must be at least %d devices to reconstruct the secret!\n", G_POLYDEGREE+1);
        return 0;
    }

    BN_dec2bn(&secret, "0");
    BIGNUM *sk_i = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (paiShamir_interpolation, paishamir)\n");
        goto end;
    }

    for (int i = 0; i < size_of_list; i++) {
        err = part_interpolation(devices_list, size_of_list, i, q, sk_i);
        if(err != 1)
        {
            printf(" * Interpolation of PART %d failed! (paiShamir_interpolation, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_add(secret, secret, sk_i, q, ctx);
        if(err != 1)
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

unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, BIGNUM *q, BIGNUM *sk_i) {
    unsigned int err = 0;
    BIGNUM *tmp_mul = BN_new();
    BIGNUM *sub = BN_new();
    BIGNUM *inv = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (part_interpolation, paishamir)\n");
        goto end;
    }
    
    BN_copy(sk_i, g_ssaka_devicesKeys[devices_list[current_device]].sk);
    for (int i = 0; i < size_of_list; i++) {
        if(current_device == i)
            continue;
        err = BN_mod_sub(sub, g_ssaka_devicesKeys[devices_list[i]].pk, g_ssaka_devicesKeys[devices_list[current_device]].pk, q, ctx);
        if(err != 1)
        {
            printf(" * Computation of SUB (%d) failed! (part_interpolation, paishamir)\n", i);
            goto end;
        }
        if(!BN_mod_inverse(inv, sub, q, ctx))
        {
            printf(" * Computation of INV (%d) failed! (part_interpolation, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_mul(tmp_mul, g_ssaka_devicesKeys[devices_list[i]].pk, inv, q, ctx);
        if(err != 1)
        {
            printf(" * Computation of TMP_MUL (%d) failed! (part_interpolation, paishamir)\n", i);
            goto end;
        }
        err = BN_mod_mul(sk_i, sk_i, tmp_mul, q, ctx);
        if(err != 1)
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