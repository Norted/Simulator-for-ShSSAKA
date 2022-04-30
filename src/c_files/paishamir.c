#include <paishamir.h>

unsigned int _shamir_distribution(unsigned char *secret) {
    unsigned int err = 0;
    
    // SHARE
    unsigned char sum[BUFFER];
    unsigned char polynom[G_POLYDEGREE+1][BUFFER];
    strcpy(polynom[0], secret);
    for (int j = 1; j < G_POLYDEGREE+1; j++) {
        err += random_str_num_in_range(polynom[j], atoi(g_globals.params->q)-1, 1);
    }
    //printf("ERR: %u\n POLY:\n|-> %s\n|-> %s\n|-> %s\n", err, polynom[0], polynom[1], polynom[2]);
    
    for (int i = 0; i < currentNumberOfDevices; i++) {
        unsigned char xs[G_POLYDEGREE+1][BUFFER];
        unsigned char str_i[BUFFER];
        for (int z = 0; z <= G_POLYDEGREE; z++) {
            sprintf(str_i, "%d", z);
            err += bn_modexp(g_ssaka_devicesKeys[i].keys->pk, str_i, g_globals.params->q, xs[z]);
        }
        //printf("PK: %s\n XS:\n|-> %s\n|-> %s\n|-> %s\n", g_ssaka_devicesKeys[i].keys->pk, xs[0], xs[1], xs[2]);

        strcpy(sum, "0");
        unsigned char ci_tmp[BUFFER];
        printf("I %d: ", i);
        for(int u = 0; u < G_POLYDEGREE+1; u++) {
            printf("%s * %s\t", polynom[u], xs[u]);
            err += bn_modmul(polynom[u], xs[u], g_globals.params->q, ci_tmp);
            err += bn_modadd(sum, ci_tmp, g_globals.params->q, sum);
        }
        strcpy(g_ssaka_devicesKeys[i].keys->sk, sum);
        printf("\nSK_%d: %s\n\n", i, g_ssaka_devicesKeys[i].keys->sk);
    }

    printf("ERR: %d\n", err);
    return 1;
}

unsigned int paiShamir_distribution(struct paillierKeychain *paikeys) {
    unsigned int err = 0;


    unsigned char SUM[BUFFER];
    strcpy(SUM, "0");
    unsigned int interpolation_list[currentNumberOfDevices];
    for (int i = 0; i < currentNumberOfDevices; i++) {
        interpolation_list[i] = i;
    }
    unsigned int part_interpolation_list[] = {0, 1, 2};
    unsigned int size = sizeof(part_interpolation_list) / sizeof(unsigned int);


    unsigned char c[BUFFER];
    unsigned char ci[BUFFER];
    unsigned char cN_prime[BUFFER];
    unsigned char kappa_i[currentNumberOfDevices][BUFFER];
    unsigned char d[currentNumberOfDevices][G_POLYDEGREE][BUFFER];
    for (int i = 0; i < currentNumberOfDevices; i++) {
        //printf("I: %d\t", i);
        err += random_str_num_in_range(kappa_i[i], atoi(paikeys->pk.n)-1, 1);
        //printf("KAPPA: %s\n", kappa_i[i]);
        //err += bn_add(SUM, kappa_i[i], SUM);
        for(int j = 0; j < G_POLYDEGREE; j++) {
            err += random_str_num_in_range(d[i][j], atoi(paikeys->pk.n)-1, 1);
        }
    }
    //printf("\n");
    
    // SHARE
    for (int i = 0; i < currentNumberOfDevices; i++) {
        err += paiShamir_get_ci(paikeys, kappa_i[i], d[i], g_ssaka_devicesKeys[i].keys->pk, c);
        err += paiShamir_get_ci(paikeys, kappa_i[(i+1)%(currentNumberOfDevices)], d[(i+1)%(currentNumberOfDevices)], g_ssaka_devicesKeys[i].keys->pk, cN_prime);
        for (int j = 0; j < currentNumberOfDevices; j++) {
            if(j == i || j == (i+1)%(currentNumberOfDevices))
                continue;
            //printf("|--> J: %d\t", j);
            err += paiShamir_get_ci(paikeys, kappa_i[j], d[j], g_ssaka_devicesKeys[i].keys->pk, ci);
            err += paiShamir_get_cN_prime(paikeys, cN_prime, ci, cN_prime);
        }
        err += paiShamir_get_share(paikeys, cN_prime, c, g_ssaka_devicesKeys[i].keys->sk);

        //err += bn_add(SUM, g_ssaka_devicesKeys[i].keys->sk, SUM);
        //printf("SK_%d: %s\n", i, g_ssaka_devicesKeys[i].keys->sk);
    }

    printf("\n~~~ DEBUG TEST ~~~\n");
    err += paiShamir_interpolation(interpolation_list, currentNumberOfDevices, SUM);
    printf("SK_SUM: %s\n", SUM);
    err += bn_modexp(g_globals.params->g,SUM,g_globals.params->p,SUM);
    printf("~ PK: %s\n\n", SUM);
    
    err += paiShamir_interpolation(part_interpolation_list, size, SUM);
    printf("INTER_SK: %s\n", SUM);
    err += bn_modexp(g_globals.params->g,SUM,g_globals.params->p,SUM);
    printf("~ PK: %s\n", SUM);
    printf("~~~~~~~~~~~~~~~~~~\n\n");

    if(err != (currentNumberOfDevices) * (4 + 2*(currentNumberOfDevices-2) + G_POLYDEGREE))
        return 0;
    return 1;
}

unsigned int paiShamir_get_ci(struct paillierKeychain *paikeys, unsigned char *kappa_i, unsigned char d[G_POLYDEGREE][BUFFER], unsigned char *x, unsigned char *ci) {
    unsigned int err = 0;
    int i = 0;

    // POLYNOM CREATION
    unsigned char polynom[G_POLYDEGREE+1][BUFFER];
    err += encrypt(paikeys->pk, kappa_i, polynom[0]);
    for (int i = 1; i < G_POLYDEGREE+1; i++) {
        err += encrypt(paikeys->pk, d[i-1], polynom[i]);
    }
    //printf("ERR: %u\n POLY:\n|-> %s\n|-> %s\n|-> %s\n", err, polynom[0], polynom[1], polynom[2]);

    unsigned char xs[G_POLYDEGREE+1][BUFFER];
    unsigned char str_i[BUFFER];
    for (i = 0; i <= G_POLYDEGREE; i++) {
        sprintf(str_i, "%d", i);
        err += bn_modexp(x, str_i, paikeys->pk.n, xs[i]);
    }

    strcpy(ci, "1");
    unsigned char ci_tmp[BUFFER];
    for(i = 0; i < G_POLYDEGREE+1; i++) {
        err += mul_const(paikeys->pk, polynom[i], xs[i], ci_tmp);
        err += add(paikeys->pk, ci, ci_tmp, ci);
    }

    if(err != 1 + G_POLYDEGREE + 3 * (G_POLYDEGREE+1))
        return 0;
    
    return 1;
}

unsigned int paiShamir_get_cN_prime(struct paillierKeychain *paikeys, unsigned char *pre_cN, unsigned char *cN, unsigned char *cN_prime) {
    return add(paikeys->pk, pre_cN, cN, cN_prime);
}

unsigned int paiShamir_get_share(struct paillierKeychain *paikeys, unsigned char *cN_prime, unsigned char *c, unsigned char *share) {
    unsigned int err = 0;
    unsigned char enc[BUFFER];
    err += add(paikeys->pk, c, cN_prime, enc);
    err += decrypt(paikeys, enc, share);

    if(err != 2)
        return 0;
    
    return 1;
}

unsigned int paiShamir_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned char *secret) {
    unsigned int err = 0;
    if(size_of_list <= G_POLYDEGREE) {
        printf("There must be at least %d devices to reconstruct the secret!\n", G_POLYDEGREE+1);
        return 0;
    }

    strcpy(secret, "0");
    unsigned char sk_i[BUFFER];
    for (int j = 0; j < size_of_list; j++) {
        err += part_interpolation(devices_list, size_of_list, j, sk_i);
        err += bn_modadd(secret, sk_i, g_globals.params->q, secret);
    }

    if(err != 2 * size_of_list)
        return 0;
    
    return 1;
}

unsigned int part_interpolation(unsigned int *devices_list, unsigned int size_of_list, unsigned int current_device, unsigned char *sk_i) {
    unsigned int err = 0;
    unsigned char tmp_mul[BUFFER];
    unsigned char sub[BUFFER];
    unsigned char inv[BUFFER];
    
    strcpy(sk_i, g_ssaka_devicesKeys[devices_list[current_device]].keys->sk);
    for (int m = 0; m < size_of_list; m++) {
        if(current_device == m)
            continue;
        err += bn_modsub(g_ssaka_devicesKeys[devices_list[m]].keys->pk, g_ssaka_devicesKeys[devices_list[current_device]].keys->pk, g_globals.params->q, sub);
        err += bn_modinverse(sub, g_globals.params->q, inv);
        err += bn_modmul(g_ssaka_devicesKeys[devices_list[m]].keys->pk, inv, g_globals.params->q, tmp_mul);
        err += bn_modmul(sk_i, tmp_mul, g_globals.params->q, sk_i);
    }

    if(err != (size_of_list-1)*4)
        return 0;

    return 1;
}