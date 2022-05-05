#include <paishamir_OLD.h>

unsigned int _shamir_distribution(BIGNUM *secret) {
    unsigned int err = 0;
    
    // SHARE
    BIGNUM *sum = BN_new();
    BIGNUM *polynom[G_POLYDEGREE+1];
    BN_copy(polynom[0], secret);
    for (int j = 1; j < G_POLYDEGREE+1; j++) {
        polynom[j] = BN_new();
        err = rand_range(polynom[j], g_globals.params->q);
    }
    //printf("ERR: %u\n POLY:\n|-> %s\n|-> %s\n|-> %s\n", err, polynom[0], polynom[1], polynom[2]);
    
    BIGNUM *xs[G_POLYDEGREE+1];
    BN_CTX *ctx = BN_CTX_secure_new();
    unsigned char *str_i = (char *)malloc(sizeof(char)*BUFFER);
    for (int i = 0; i < currentNumberOfDevices; i++) {
        for (int z = 0; z <= G_POLYDEGREE; z++) {
            xs[i] = BN_new();
            sprintf(str_i, "%d", z);
            err = BN_mod_exp(xs[z], g_ssaka_devicesKeys[i].keys->pk, str_i, g_globals.params->q, ctx);
        }
        //printf("PK: %s\n XS:\n|-> %s\n|-> %s\n|-> %s\n", g_ssaka_devicesKeys[i].keys->pk, xs[0], xs[1], xs[2]);

        BN_dec2bn(&sum, "0");
        BIGNUM *ci_tmp = BN_new();
        printf("I %d: ", i);
        for(int u = 0; u < G_POLYDEGREE+1; u++) {
            printf("%s * %s\t", polynom[u], xs[u]);
            err = BN_mod_mul(ci_tmp, polynom[u], xs[u], g_globals.params->q, ctx);
            err = BN_mod_add(sum, sum, ci_tmp, g_globals.params->q, ctx);
        }
        BN_copy(g_ssaka_devicesKeys[i].keys->sk, sum);
        printf("\nSK_%d: %s\n\n", i, BN_bn2dec(g_ssaka_devicesKeys[i].keys->sk));
    }

    printf("ERR: %d\n", err);
    return err;
}

unsigned int paiShamir_distribution(struct paillier_Keychain *paikeys) {
    unsigned int err = 0;


    /* unsigned char SUM[BUFFER];
    strcpy(SUM, "0");
    unsigned int interpolation_list[currentNumberOfDevices];
    for (int i = 0; i < currentNumberOfDevices; i++) {
        interpolation_list[i] = i;
    }
    unsigned int part_interpolation_list[] = {0, 1, 2};
    unsigned int size = sizeof(part_interpolation_list) / sizeof(unsigned int); */


    BIGNUM *c = BN_new();
    BIGNUM *ci = BN_new();
    BIGNUM *cN_prime = BN_new();
    BIGNUM *kappa_i[currentNumberOfDevices];
    BIGNUM *d[currentNumberOfDevices][G_POLYDEGREE];
    for (int i = 0; i < currentNumberOfDevices; i++) {
        //printf("I: %d\t", i);
        kappa_i[i] = BN_new();
        err = rand_range(kappa_i[i], paikeys->pk->n);
        //printf("KAPPA: %s\n", kappa_i[i]);
        //err += bn_add(SUM, kappa_i[i], SUM);
        for(int j = 0; j < G_POLYDEGREE; j++) {
            d[i][j] = BN_new();
            err = rand_range(d[i][j], paikeys->pk->n);
        }
    }
    //printf("\n");
    
    // SHARE
    for (int i = 0; i < currentNumberOfDevices; i++) {
        err = paiShamir_get_ci(paikeys, kappa_i[i], d[i], g_ssaka_devicesKeys[i].keys->pk, c);
        err = paiShamir_get_ci(paikeys, kappa_i[(i+1)%(currentNumberOfDevices)], d[(i+1)%(currentNumberOfDevices)], g_ssaka_devicesKeys[i].keys->pk, cN_prime);
        for (int j = 0; j < currentNumberOfDevices; j++) {
            if(j == i || j == (i+1)%(currentNumberOfDevices))
                continue;
            //printf("|--> J: %d\t", j);
            err = paiShamir_get_ci(paikeys, kappa_i[j], d[j], g_ssaka_devicesKeys[i].keys->pk, ci);
            err = paiShamir_get_cN_prime(paikeys, cN_prime, ci, cN_prime);
        }
        err = paiShamir_get_share(paikeys, cN_prime, c, g_ssaka_devicesKeys[i].keys->sk);

        //err += bn_add(SUM, g_ssaka_devicesKeys[i].keys->sk, SUM);
        //printf("SK_%d: %s\n", i, g_ssaka_devicesKeys[i].keys->sk);
    }

    /* printf("\n~~~ DEBUG TEST ~~~\n");
    err += paiShamir_interpolation(interpolation_list, currentNumberOfDevices, SUM);
    printf("SK_SUM: %s\n", SUM);
    err += bn_modexp(g_globals.params->g,SUM,g_globals.params->p,SUM);
    printf("~ PK: %s\n\n", SUM);
    
    err += paiShamir_interpolation(part_interpolation_list, size, SUM);
    printf("INTER_SK: %s\n", SUM);
    err += bn_modexp(g_globals.params->g,SUM,g_globals.params->p,SUM);
    printf("~ PK: %s\n", SUM);
    printf("~~~~~~~~~~~~~~~~~~\n\n"); */

    if(err != 1)
        return 0;
    return 1;
}

unsigned int paiShamir_get_ci(struct paillier_Keychain *paikeys, BIGNUM *kappa_i, BIGNUM *d[G_POLYDEGREE], BIGNUM *x, BIGNUM *ci) {
    unsigned int err = 0;
    int i = 0;

    // POLYNOM CREATION
    BIGNUM *polynom[G_POLYDEGREE+1];
    BIGNUM *zero = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    BN_dec2bn(&zero, "0");
    polynom[0] = BN_new();
    err = paillier_encrypt(paikeys->pk, kappa_i, polynom[0], zero, zero);
    for (int i = 1; i < G_POLYDEGREE+1; i++) {
        polynom[i] = BN_new();
        err = paillier_encrypt(paikeys->pk, d[i-1], polynom[i], zero, zero);
    }
    //printf("ERR: %u\n POLY:\n|-> %s\n|-> %s\n|-> %s\n", err, polynom[0], polynom[1], polynom[2]);

    BIGNUM *xs[G_POLYDEGREE+1];
    unsigned char *str_i = (char*)malloc(sizeof(char) * BUFFER);
    for (i = 0; i <= G_POLYDEGREE; i++) {
        xs[i] = BN_new();
        sprintf(str_i, "%d", i);
        err = BN_mod_exp(xs[i], x, str_i, paikeys->pk->n, ctx);
    }

    BN_dec2bn(&ci, "1");
    BIGNUM *ci_tmp = BN_new();
    for(i = 0; i < G_POLYDEGREE+1; i++) {
        err = homomorphy_mul_const(paikeys->pk, polynom[i], xs[i], ci_tmp);
        err = homomorphy_add(paikeys->pk, ci, ci_tmp, ci);
    }

    if(err != 1)
        return 0;
    
    return 1;
}

unsigned int paiShamir_get_cN_prime(struct paillier_Keychain *paikeys, BIGNUM *pre_cN, BIGNUM *cN, BIGNUM *cN_prime) {
    return homomorphy_add(paikeys->pk, pre_cN, cN, cN_prime);
}

unsigned int paiShamir_get_share(struct paillier_Keychain *paikeys, BIGNUM *cN_prime, BIGNUM *c, BIGNUM *share) {
    unsigned int err = 0;
    BIGNUM *enc = BN_new();
    err = homomorphy_add(paikeys->pk, c, cN_prime, enc);
    err = paillier_decrypt(paikeys, enc, share);

    if(err != 1)
        return 0;
    
    return 1;
}

unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, BIGNUM *secret) {
    unsigned int err = 0;
    if(size_of_list <= G_POLYDEGREE) {
        printf("There must be at least %d devices to reconstruct the secret!\n", G_POLYDEGREE+1);
        return 0;
    }

    BN_dec2bn(&secret, "0");
    BIGNUM *sk_i = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    for (int j = 0; j < size_of_list; j++) {
        err = part_interpolation(devices_list, size_of_list, j, sk_i);
        err = BN_mod_add(secret, secret, sk_i, g_globals.params->q, ctx);
    }

    if(err != 1)
        return 0;
    
    return 1;
}

unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, BIGNUM *sk_i) {
    unsigned int err = 0;
    BIGNUM *tmp_mul = BN_new();
    BIGNUM *sub = BN_new();
    BIGNUM *inv = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    
    BN_copy(sk_i, g_ssaka_devicesKeys[devices_list[current_device]].keys->sk);
    for (int m = 0; m < size_of_list; m++) {
        if(current_device == m)
            continue;
        err = BN_mod_sub(sub, g_ssaka_devicesKeys[devices_list[m]].keys->pk, g_ssaka_devicesKeys[devices_list[current_device]].keys->pk, g_globals.params->q, ctx);
        err = BN_mod_inverse(inv, sub, g_globals.params->q, ctx);
        err = BN_mod_mul(tmp_mul, g_ssaka_devicesKeys[devices_list[m]].keys->pk, inv, g_globals.params->q, ctx);
        err = BN_mod_mul(sk_i, sk_i, tmp_mul, g_globals.params->q, ctx);
    }

    if(err != 1)
        return 0;

    return 1;
}