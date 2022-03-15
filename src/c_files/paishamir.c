#include <paishamir.h>

unsigned int _shamir_distribution(BIGNUM *secret)
{
    unsigned int err = 0;
    int i = 0;

    // SHARE
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (paishamir, _shamir_distribution)\n");
        goto end;
    }

    BIGNUM *sum = BN_new();
    BIGNUM *polynom[G_POLYDEGREE + 1];
    BIGNUM *xs[G_POLYDEGREE + 1];
    BIGNUM *tmp_exp = BN_new();
    unsigned char *str_exp = (char *) malloc(BUFFER);
    BIGNUM *ci_tmp = BN_new();

    for (i; i <= G_POLYDEGREE; i++)
    {
        polynom[i] = BN_new();
        if (i == 0)
            BN_copy(polynom[i], secret);
        else
        {
            err = BN_rand_range_ex(polynom[i], g_globals.params->q, NULL, ctx);
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
            sprintf(str_exp, "%d", exp);
            BN_dec2bn(&tmp_exp, str_exp);
            err = BN_mod_exp(xs[exp], g_ssaka_devicesKeys[i].keys->pk, tmp_exp, g_globals.params->q, ctx);
            if(err != 1)
            {
                printf(" * Exponentation failed at EXP = %d! (paishamir, _shamir_distribution)\n", exp);
                goto end;
            }
        }

        // printf("I %d: ", i);
        for (int j = 0; j < G_POLYDEGREE + 1; j++)
        {
            // printf("%s * %s\t", BN_bn2dec(polynom[j]), BN_bn2dec(xs[j]));
            err = BN_mod_mul(ci_tmp, polynom[j], xs[j], g_globals.params->q, ctx); //bn_modmul(polynom[j], xs[j], g_globals.params->q, ci_tmp);
            if(err != 1) {
                printf(" * Modular multipliaction of polynom with share failed! (paishamir, _shamir_distribution)\n");
                goto end;
            }
            err = BN_mod_add(sum, ci_tmp, g_globals.params->q, sum, ctx); //bn_modadd(sum, ci_tmp, g_globals.params->q, sum);
            if(err != 1) {
                printf(" * Modular addition of share failed! (paishamir, _shamir_distribution)\n");
                goto end;
            }
        }
        BN_copy(g_ssaka_devicesKeys[i].keys->sk, sum);
        // printf("\nSK_%d: %s\n\n", i, g_ssaka_devicesKeys[i].keys->sk);
        
        BN_dec2bn(&sum, "0");
    }

end:
    BN_CTX_free(ctx);
    BN_free(sum);
    for(i = 0; i <= G_POLYDEGREE; i++)
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

    BIGNUM *c = BN_new();
    BIGNUM *ci = BN_new();
    BIGNUM *cN_prime = BN_new();
    BIGNUM *kappa_i[currentNumberOfDevices];
    BIGNUM *d[currentNumberOfDevices][G_POLYDEGREE];

    // TODO: !!!!
    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        // printf("I: %d\t", i);
        err += random_str_num_in_range(kappa_i[i], atoi(paikeys->pk.n) - 1, 1);
        // printf("KAPPA: %s\n", kappa_i[i]);
        // err += bn_add(SUM, kappa_i[i], SUM);
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            err += random_str_num_in_range(d[i][j], atoi(paikeys->pk.n) - 1, 1);
        }
    }
    // printf("\n");

    // SHARE
    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        err += paiShamir_get_ci(paikeys, kappa_i[i], d[i], g_ssaka_devicesKeys[i].keys->pk, c);
        err += paiShamir_get_ci(paikeys, kappa_i[(i + 1) % (currentNumberOfDevices)], d[(i + 1) % (currentNumberOfDevices)], g_ssaka_devicesKeys[i].keys->pk, cN_prime);
        for (int j = 0; j < currentNumberOfDevices; j++)
        {
            if (j == i || j == (i + 1) % (currentNumberOfDevices))
                continue;
            // printf("|--> J: %d\t", j);
            err += paiShamir_get_ci(paikeys, kappa_i[j], d[j], g_ssaka_devicesKeys[i].keys->pk, ci);
            err += paiShamir_get_cN_prime(paikeys, cN_prime, ci, cN_prime);
        }
        err += paiShamir_get_share(paikeys, cN_prime, c, g_ssaka_devicesKeys[i].keys->sk);
        // printf("SK_%d: %s\n", i, g_ssaka_devicesKeys[i].keys->sk);
    }

    // printf("\nKappa_SUM: %s\n\n", SUM);
    // err += bn_modexp(g_globals.params->g,SUM,g_globals.params->q,SUM);
    // printf("\nKappa_PK: %s\n\n", SUM);

    if (err != (currentNumberOfDevices) * (4 + 2 * (currentNumberOfDevices - 2) + G_POLYDEGREE))
        return 0;
    return 1;
}

unsigned int paiShamir_get_ci(struct paillierKeychain *paikeys, BIGNUM *kappa_i, BIGNUM d[G_POLYDEGREE][BUFFER], BIGNUM *x, BIGNUM *ci)
{
    unsigned int err = 0;
    int i = 0;

    // POLYNOM CREATION
    BIGNUM polynom[G_POLYDEGREE + 1][BUFFER];
    err += encrypt(paikeys->pk, kappa_i, polynom[0]);
    for (int i = 1; i < G_POLYDEGREE + 1; i++)
    {
        err += encrypt(paikeys->pk, d[i - 1], polynom[i]);
    }
    // printf("ERR: %j\n POLY:\n|-> %s\n|-> %s\n|-> %s\n", err, polynom[0], polynom[1], polynom[2]);

    BIGNUM xs[G_POLYDEGREE + 1][BUFFER];
    BIGNUM str_i[BUFFER];
    for (i = 0; i <= G_POLYDEGREE; i++)
    {
        sprintf(str_i, "%d", i);
        err += bn_modexp(x, str_i, paikeys->pk.n, xs[i]);
    }

    strcpy(ci, "1");
    BIGNUM ci_tmp[BUFFER];
    for (i = 0; i < G_POLYDEGREE + 1; i++)
    {
        err += mul_const(paikeys->pk, polynom[i], xs[i], ci_tmp);
        err += add(paikeys->pk, ci, ci_tmp, ci);
    }

    if (err != 1 + G_POLYDEGREE + 3 * (G_POLYDEGREE + 1))
        return 0;

    return 1;
}

unsigned int paiShamir_get_cN_prime(struct paillierKeychain *paikeys, BIGNUM *pre_cN, BIGNUM *cN, BIGNUM *cN_prime)
{
    return add(paikeys->pk, pre_cN, cN, cN_prime);
}

unsigned int paiShamir_get_share(struct paillierKeychain *paikeys, BIGNUM *cN_prime, BIGNUM *c, BIGNUM *share)
{
    unsigned int err = 0;
    BIGNUM enc[BUFFER];
    err += add(paikeys->pk, c, cN_prime, enc);
    err += decrypt(paikeys, enc, share);

    if (err != 2)
        return 0;

    return 1;
}

unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, BIGNUM *secret)
{
    unsigned int err = 0;
    if (size_of_list <= G_POLYDEGREE)
    {
        printf("There must be at least %d devices to reconstruct the secret!\n", G_POLYDEGREE + 1);
        return 0;
    }

    strcpy(secret, "0");
    BIGNUM sk_i[BUFFER];
    for (int j = 0; j < size_of_list; j++)
    {
        err += part_interpolation(devices_list, size_of_list, j, sk_i);
        err += bn_modadd(secret, sk_i, g_globals.params->q, secret);
    }

    if (err != 2 * size_of_list)
        return 0;

    return 1;
}

unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, BIGNUM *sk_i)
{
    unsigned int err = 0;
    BIGNUM tmp_mul[BUFFER];
    BIGNUM sub[BUFFER];
    BIGNUM inv[BUFFER];

    strcpy(sk_i, g_ssaka_devicesKeys[devices_list[current_device]].keys->sk);
    for (int m = 0; m < size_of_list; m++)
    {
        if (current_device == m)
            continue;
        err += bn_modsub(g_ssaka_devicesKeys[devices_list[m]].keys->pk, g_ssaka_devicesKeys[devices_list[current_device]].keys->pk, g_globals.params->q, sub);
        err += bn_modinverse(sub, g_globals.params->q, inv);
        err += bn_modmul(g_ssaka_devicesKeys[devices_list[m]].keys->pk, inv, g_globals.params->q, tmp_mul);
        err += bn_modmul(sk_i, tmp_mul, g_globals.params->q, sk_i);
    }

    if (err != (size_of_list - 1) * 4)
        return 0;

    return 1;
}