#include <paishamir_OLD.h>

unsigned int _shamir_distribution(BIGNUM *secret)
{
    unsigned int err = 0;
    int i = 0;

    // SHARE
    BIGNUM *sum = BN_new();
    BIGNUM *polynom[G_POLYDEGREE + 1];
    BIGNUM *xs[G_POLYDEGREE + 1];
    BIGNUM *tmp_exp = BN_new();
    unsigned char *str_exp = malloc(sizeof(unsigned char) * BUFFER);
    BIGNUM *ci_tmp = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (paishamir, _shamir_distribution)\n");
        goto end;
    }

    for (i; i <= G_POLYDEGREE; i++)
    {
        polynom[i] = BN_new();
        if (i == 0)
            BN_copy(polynom[i], secret);
        else
        {
            err = rand_range(polynom[i], g_globals.params->q);
            if (err != 1)
            {
                printf(" * Generate random polynom failed! (paishamir, _shamir_distribution)\n");
                goto end;
            }
        }
    }

    for (i = 0; i < currentNumberOfDevices; i++)
    {
        for (int exp = 0; exp <= G_POLYDEGREE; exp++)
        {
            xs[exp] = BN_new();

            sprintf(str_exp, "%d", exp);
            BN_dec2bn(&tmp_exp, str_exp);
            err = BN_mod_exp(xs[exp], g_ssaka_devicesKeys[i].keys->pk, tmp_exp, g_globals.params->p, ctx);
            if (err != 1)
            {
                printf(" * Exponentation failed at EXP = %d! (paishamir, _shamir_distribution)\n", exp);
                goto end;
            }
            // printf("PK: %s\n XS:\n|-> %s\n|-> %s\n|-> %s\n", BN_bn2dec(g_ssaka_devicesKeys[i].keys->pk), BN_bn2dec(xs[0]), BN_bn2dec(xs[1]), BN_bn2dec(xs[2]));
        }

        for (int j = 0; j <= G_POLYDEGREE; j++)
        {
            err = BN_mod_mul(ci_tmp, polynom[j], xs[j], g_globals.params->p, ctx);
            if (err != 1)
            {
                printf(" * Modular multipliaction of polynom with share failed! (paishamir, _shamir_distribution)\n");
                goto end;
            }
            err = BN_mod_add(sum, sum, ci_tmp, g_globals.params->p, ctx);
            if (err != 1)
            {
                printf(" * Modular addition of share failed! (paishamir, _shamir_distribution)\n");
                goto end;
            }
        }
        BN_copy(g_ssaka_devicesKeys[i].keys->sk, sum);
    }

end:
    BN_CTX_free(ctx);
    BN_free(sum);
    for (i = 0; i <= G_POLYDEGREE; i++)
    {
        BN_free(polynom[i]);
        BN_free(xs[i]);
    }
    BN_free(tmp_exp);
    free(str_exp);
    BN_free(ci_tmp);
    return err;
}

unsigned int paiShamir_distribution(struct paillier_Keychain *paikeys)
{
    unsigned int err = 0;
    int i = 0;

    // DEBUG CODE
        BN_CTX *ctx = BN_CTX_secure_new();
        BIGNUM *SK = BN_new();
        BIGNUM *part_SK = BN_new();
        BIGNUM *l_pk_c = BN_new();
        unsigned int full_interpolation_list[currentNumberOfDevices];
        for(i; i < currentNumberOfDevices; i++)
        {
            full_interpolation_list[i] = i;
        }
        unsigned int partial_interpolation_list[] = {0, 1, 2};
        unsigned int size_part_list = sizeof(partial_interpolation_list) / sizeof(unsigned int);
    //

    BIGNUM *c = BN_new();
    BIGNUM *ci = BN_new();
    BIGNUM *cN_prime = BN_new();
    BIGNUM *kappa_i[currentNumberOfDevices];
    BIGNUM *d[currentNumberOfDevices][G_POLYDEGREE];

    for (i = 0; i < currentNumberOfDevices; i++)
    {
        kappa_i[i] = BN_new();
        err = rand_range(kappa_i[i], paikeys->pk->n); // ->q
        if (err != 1)
        {
            printf(" * Failed to generate random KAPPA_i value! (paishamir, paiShamir_distribution)\n");
            goto end;
        }

        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            d[i][j] = BN_new();
            err = rand_range(d[i][j], paikeys->pk->n); // ->q
            if (err != 1)
            {
                printf(" * Failed to generate random D value! (paishamir, paiShamir_distribution)\n");
                goto end;
            }
        }
    }
    /* printf("\n"); */

    // SHARE
    for (i = 0; i < currentNumberOfDevices; i++)
    {        
        err = paiShamir_get_ci(paikeys, kappa_i[i], d[i], g_ssaka_devicesKeys[i].keys->pk, c);
        if (err != 1)
        {
            printf(" * Failed to get first C_i! (paishamir, paiShamir_distribution)\n");
            goto end;
        }
        err = paiShamir_get_ci(paikeys, kappa_i[(i + 1) % (currentNumberOfDevices)], d[(i + 1) % (currentNumberOfDevices)], g_ssaka_devicesKeys[i].keys->pk, cN_prime);
        if (err != 1)
        {
            printf(" * Failed to get second C_i! (paishamir, paiShamir_distribution)\n");
            goto end;
        }
        for (int j = 0; j < currentNumberOfDevices; j++)
        {
            if (j == i || j == (i + 1) % (currentNumberOfDevices))
                continue;
            
            /* printf("|--> J: %d\t", j); */
            
            err = paiShamir_get_ci(paikeys, kappa_i[j], d[j], g_ssaka_devicesKeys[i].keys->pk, ci);
            if (err != 1)
            {
                printf(" * Failed to get %d C_i! (paishamir, paiShamir_distribution)\n", j);
                goto end;
            }
            err = paiShamir_get_cN_prime(paikeys, cN_prime, ci, cN_prime);
            if (err != 1)
            {
                printf(" * Failed to get C_n_prime value! (paishamir, paiShamir_distribution)\n");
                goto end;
            }
        }
        err = paiShamir_get_share(paikeys, cN_prime, c, g_ssaka_devicesKeys[i].keys->sk);
        if (err != 1)
        {
            printf(" * Failed to get share! (paishamir, paiShamir_distribution)\n");
            goto end;
        }
        
        //printf("SK_%d: %s\n", i, BN_bn2dec(g_ssaka_devicesKeys[i].keys->sk));
    }
    
    // DEBUG CODE
        printf("\n~~~ PaiShamir DEBUG ~~~\n");
        err = paiShamir_interpolation(full_interpolation_list, currentNumberOfDevices, SK);
        printf(">> SK: %s\n", BN_bn2dec(SK));
        err = BN_mod_exp(l_pk_c, g_globals.params->g, SK, g_globals.params->p, ctx);
        printf(">> ~ PK_C: %s\n", BN_bn2dec(l_pk_c));

        err = paiShamir_interpolation(partial_interpolation_list, size_part_list, part_SK);
        printf(">> part_SK: %s\n", BN_bn2dec(part_SK));
        err = BN_mod_exp(l_pk_c, g_globals.params->g, part_SK, g_globals.params->p, ctx);
        printf(">> ~ PK_C: %s\n", BN_bn2dec(l_pk_c));
        printf("~~~~~~~~~~~~~~~~~~~~~~~\n\n");
    //

end:
    BN_free(c);
    BN_free(ci);
    BN_free(cN_prime);
    // DEBUG CODE
        BN_free(SK);
        BN_free(part_SK);
        BN_free(l_pk_c);
        BN_CTX_free(ctx);
    //
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

unsigned int paiShamir_get_ci(struct paillier_Keychain *paikeys, BIGNUM *kappa_i, BIGNUM *d[], BIGNUM *x, BIGNUM *ci)
{
    unsigned int err = 0;
    int i = 0;

    // POLYNOM CREATION
    BIGNUM *polynom[G_POLYDEGREE + 1];
    BIGNUM *xs[G_POLYDEGREE + 1];
    unsigned char *str_exp = malloc(sizeof(unsigned char) * BUFFER);
    BIGNUM *tmp_exp = BN_new();
    BIGNUM *ci_tmp = BN_new();

    BIGNUM *zero1 = BN_new();
    BN_dec2bn(&zero1, "0");
    BIGNUM *zero2 = BN_new();
    BN_dec2bn(&zero2, "0");

    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (paishamir, paiShamir_get_ci)\n");
        goto end;
    }

    polynom[0] = BN_new();
    err = paillier_encrypt(paikeys->pk, kappa_i, polynom[0], zero1, zero2);
    if (err != 1)
    {
        printf(" * Failed to encrypt polynom 0! (paishamir, paiShamir_get_ci)\n");
        goto end;
    }

    for (i = 1; i <= G_POLYDEGREE; i++)
    {
        BN_dec2bn(&zero1, "0");
        BN_dec2bn(&zero2, "0");
        polynom[i] = BN_new();

        err = paillier_encrypt(paikeys->pk, d[i - 1], polynom[i], zero1, zero2);
        if (err != 1)
        {
            printf(" * Failed to encrypt polynom %d! (paishamir, paiShamir_get_ci)\n", i);
            goto end;
        }
    }

    for (i = 0; i <= G_POLYDEGREE; i++)
    {
        xs[i] = BN_new();

        sprintf(str_exp, "%d", i);
        BN_dec2bn(&tmp_exp, str_exp);

        err = BN_mod_exp(xs[i], x, tmp_exp, paikeys->pk->n, ctx);
        if (err != 1)
        {
            printf(" * Failed to compute %d. xs! (paishamir, paiShamir_get_ci)\n", i);
            goto end;
        }
    }

    BN_dec2bn(&ci, "1");
    for (i = 0; i <= G_POLYDEGREE; i++)
    {
        err = homomorphy_mul_const(paikeys->pk, polynom[i], xs[i], ci_tmp);
        if (err != 1)
        {
            printf(" * Multiply ciphertext with const failed! (paishamir, paiShamir_get_ci)\n");
            goto end;
        }
        err = homomorphy_add(paikeys->pk, ci, ci_tmp, ci);
        if (err != 1)
        {
            printf(" * Add ciphertext failed! (paishamir, paiShamir_get_ci)\n");
            goto end;
        }
    }

end:
    free(str_exp);
    BN_free(tmp_exp);
    BN_free(ci_tmp);
    for (i = 0; i <= G_POLYDEGREE; i++)
    {
        BN_free(polynom[i]);
        BN_free(xs[i]);
    }
    BN_CTX_free(ctx);

    return err;
}

unsigned int paiShamir_get_cN_prime(struct paillier_Keychain *paikeys, BIGNUM *pre_cN, BIGNUM *cN, BIGNUM *cN_prime)
{
    return homomorphy_add(paikeys->pk, pre_cN, cN, cN_prime);
}

unsigned int paiShamir_get_share(struct paillier_Keychain *paikeys, BIGNUM *cN_prime, BIGNUM *c, BIGNUM *share)
{
    unsigned int err = 0;
    BIGNUM *enc = BN_new();
    err = homomorphy_add(paikeys->pk, c, cN_prime, enc);
    if (err != 1)
    {
        printf(" * Failed to add ciphertexts! (paishamir, paiShamir_get_share)\n");
        goto end;
    }
    err = paillier_decrypt(paikeys, enc, share);
    if (err != 1)
    {
        printf(" * Failed do decrypt the share! (paishamir, paiShamir_get_share)\n");
        goto end;
    }
    //printf(">> SHARE: %s\n", BN_bn2dec(share));

end:
    BN_free(enc);

    return err;
}

unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, BIGNUM *secret)
{
    unsigned int err = 0;
    BIGNUM *sk_i = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (paishamir, paiShamir_interpolation)\n");
        goto end;
    }

    if (size_of_list <= G_POLYDEGREE)
    {
        printf("There must be at least %d devices to reconstruct the secret!\n", G_POLYDEGREE + 1);
        goto end;
    }

    BN_dec2bn(&secret, "0");
    for (int i = 0; i < size_of_list; i++)
    {
        err = part_interpolation(devices_list, size_of_list, i, sk_i);
        if (err != 1)
        {
            printf(" * Part %d of the interpolation failed! (paishamir, paiShamir_interpolation)\n", i);
            goto end;
        }
        err = BN_mod_add(secret, secret, sk_i, g_globals.params->p, ctx);
        if (err != 1)
        {
            printf(" * Addition of the secret failed! (paishamir, paiShamir_interpolation)\n");
            goto end;
        }
    }

end:
    BN_free(sk_i);
    BN_CTX_free(ctx);

    return err;
}

unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, BIGNUM *sk_i)
{
    unsigned int err = 0;
    BIGNUM *tmp_mul = BN_new();
    BIGNUM *sub = BN_new();
    BIGNUM *inv = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (paishamir, part_interpolation)\n");
        goto end;
    }

    BN_copy(sk_i, g_ssaka_devicesKeys[devices_list[current_device]].keys->sk);
    for (unsigned int i = 0; i < size_of_list; i++)
    {
        if (current_device == i)
        {
            continue;
        }
        err = BN_mod_sub(sub, g_ssaka_devicesKeys[devices_list[i]].keys->pk, g_ssaka_devicesKeys[devices_list[current_device]].keys->pk, g_globals.params->p, ctx);
        if(err != 1)
        {
            printf(" * Failed to compute the residuo of the PKs (#%d)! (paishamir, part_interpolation)\n", i);
            goto end;
        }        
        if(!BN_mod_inverse(inv, sub, g_globals.params->p, ctx))
        {
            printf(" * Failed to compute the inverse (#%d)! (paishamir, part_interpolation)\n", i);
            goto end;
        }
        err = BN_mod_mul(tmp_mul, g_ssaka_devicesKeys[devices_list[i]].keys->pk, inv, g_globals.params->p, ctx);
        if(err != 1)
        {
            printf(" * Failed to multiply inverse with the PK (#%d)! (paishamir, part_interpolation)\n", i);
            goto end;
        }
        err = BN_mod_mul(sk_i, sk_i, tmp_mul, g_globals.params->p, ctx);
        if(err != 1)
        {
            printf(" * Failed to compute the SK_i #%d! (paishamir, part_interpolation)\n", i);
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