#include <ShSSAKA.h>

struct shssaka_Keychain g_shssaka_devicesKeys[G_NUMOFDEVICES];
struct paillier_Keychain g_paiKeys;
EC_POINT *pk_c;

unsigned int _get_pk_c();

/* Generate spar = (G, g, q) from session key kappa → GENERATED BY CIPHER SUITE
    int aka_Setup (int kappa) {

        return 0;
    }
*/

/* Generate pk_c and sk_c from session key kappa → GENERATED BY CIPHER SUITE
    int aka_ClientRegister (int kappa) {

        return 0;
    }
*/

unsigned int shssaka_setup()
{
    unsigned int err = 0;
    unsigned int fail = 0;
    init_shssaka_mem();

    if(paillier_inited == 0)
    {
        err = paillier_generate_keypair(&g_paiKeys);
        if (err != 1)
        {
            printf(" * Failed to generate Paillier Keychain! (SSAKA, shssaka_setup)\n");
            fail = 1;
            goto end;
        }
    }

    printf("---SERVER---\n");
    aka_keyPrinter(&g_serverKeys);
    if (!g_serverKeys.ID)
    {
        printf(" * Initialization of the SSAKA Keys failed! (SSAKA, shssaka_setup)\n");
        fail = 1;
        goto end;
    }

    int i = 0;
    // pre-init of SSAKA keys for client and other devices
    for (i; i < currentNumberOfDevices; i++)
    {
        err = shssaka_KeyGeneration(&g_shssaka_devicesKeys[i]);
        if (err != 1)
        {
            printf(" * Key generation failed (device %d)! (SSAKA, shssaka_setup)\n", i);
            fail = 1;
            goto end;
        }
    }

    err = paiShamir_distribution(&g_paiKeys);
    if (err != 1)
    {
        printf(" * Distribution of the secret failed! (SSAKA, shssaka_setup)\n");
        fail = 1;
        goto end;
    }
    err = _get_pk_c();
    if (err != 1)
    {
        printf(" * Computation of the common PK failed! (SSAKA, shssaka_setup)\n");
        fail = 1;
        goto end;
    }

    printf("--- CLIENT ---\n");
    shssaka_keyPrinter(&g_shssaka_devicesKeys[0]);

    for (i = 1; i < currentNumberOfDevices; i++)
    {
        printf("--- DEVICE %d ---\n", i);
        shssaka_keyPrinter(&g_shssaka_devicesKeys[i]);
    }

end:
    if (fail == 1)
    {
        free_shssaka_mem();
    }

    return err;
}

unsigned int shssaka_KeyGeneration(struct shssaka_Keychain *keys)
{
    unsigned int err = 0;
    
    err = rand_range(keys->pk, EC_GROUP_get0_order(g_globals.keychain->ec_group));
    if(err != 1)
    {
        printf(" * Generation of random PK failed! (shssaka_KeyGeneration, SSAKA)\n");
        return err;
    }
    keys->ID = g_globals.idCounter++;

    return err;
}

unsigned int shssaka_ClientAddShare(unsigned int num_of_new_devices)
{
    unsigned int err = 0;
    if (currentNumberOfDevices + num_of_new_devices > G_NUMOFDEVICES)
    {
        printf("Only %d places left!\n", G_NUMOFDEVICES - currentNumberOfDevices);
        return 2;
    }

    for (int i = 0; i < num_of_new_devices; i++)
    {
        g_shssaka_devicesKeys[currentNumberOfDevices + i].pk = BN_new();
        g_shssaka_devicesKeys[currentNumberOfDevices + i].sk = BN_new();
        g_shssaka_devicesKeys[currentNumberOfDevices + i].kappa = BN_new();

        err = shssaka_KeyGeneration(&g_shssaka_devicesKeys[currentNumberOfDevices + i]);
        if (err != 1)
        {
            printf(" * Key generation of device %d failed! (shssaka_ClientAddShare, SSAKA)\n", i);
            goto end;
        }
    }
    currentNumberOfDevices += num_of_new_devices;

    err = paiShamir_distribution(&g_paiKeys);
    if (err != 1)
    {
        printf(" * Distribution of the secret failed! (shssaka_ClientAddShare, SSAKA)\n");
        goto end;
    }
    err = _get_pk_c();
    if (err != 1)
    {
        printf(" * Re-computation of the common PK failed! (shssaka_ClientAddShare, SSAKA)\n");
        goto end;
    }

end:
    return err;
}

unsigned int shssaka_ClientRevShare(unsigned int rev_devices_list[], unsigned int rev_size)
{
    int i = 0;
    unsigned int err = 0;

    if (currentNumberOfDevices - rev_size < (G_POLYDEGREE + 1))
    {
        printf("Must remain at least %d devices!\n", G_POLYDEGREE + 1);
        return 2;
    }

    unsigned int index_size = currentNumberOfDevices - rev_size;
    unsigned int index_list[index_size];
    unsigned int counter = 0;

    for (i; i < rev_size; i++)
    {
        if (rev_devices_list[i] == 0)
        {
            printf("Cannot remove client (0)!\n");
            return 3;
        }
        g_shssaka_devicesKeys[rev_devices_list[i]].ID = 0;        
        g_shssaka_devicesKeys[rev_devices_list[i]].pk = BN_new();
        g_shssaka_devicesKeys[rev_devices_list[i]].sk = BN_new();
        g_shssaka_devicesKeys[rev_devices_list[i]].kappa = BN_new();
    }

    for (i = 0; i < currentNumberOfDevices; i++)
    {
        if (g_shssaka_devicesKeys[i].ID != 0)
        {
            index_list[counter++] = i;
        }
    }

    for (i = 0; i < currentNumberOfDevices; i++)
    {
        if (i < index_size)
        {
            g_shssaka_devicesKeys[i].ID = g_shssaka_devicesKeys[index_list[i]].ID;
            BN_copy(g_shssaka_devicesKeys[i].pk, g_shssaka_devicesKeys[index_list[i]].pk);
            BN_copy(g_shssaka_devicesKeys[i].sk, g_shssaka_devicesKeys[index_list[i]].sk);
            if (g_shssaka_devicesKeys[index_list[i]].kappa)
                BN_copy(g_shssaka_devicesKeys[i].kappa, g_shssaka_devicesKeys[index_list[i]].kappa);
        }
        else
        {
            g_shssaka_devicesKeys[i].ID = 0;
            BN_free(g_shssaka_devicesKeys[i].pk);
            BN_free(g_shssaka_devicesKeys[i].sk);
            BN_free(g_shssaka_devicesKeys[i].kappa);
        }
    }

    currentNumberOfDevices -= rev_size;
    err = paiShamir_distribution(&g_paiKeys);
    if (err != 1)
    {
        printf(" * Secret distribution failed! (shssaka_ClientRevShare, SSAKA)\n");
        goto end;
    }
    err = _get_pk_c();
    if (err != 1)
    {
        printf(" * Client's PK computation failed! (shssaka_ClientRevShare, SSAKA)\n");
        goto end;
    }

end:

    return err;
}

unsigned int shssaka_akaServerSignVerify(unsigned int *list_of_used_devs, unsigned int size, BIGNUM *Y, struct ServerSign *server)
{
    unsigned int err = 0;

    if (BN_is_zero(Y) == 1 || !g_serverKeys.keys->keys || BN_is_zero(g_shssaka_devicesKeys[0].pk) == 1)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf(" * Y, SERVER sk or CLIENT pk is 0! (shssaka_akaServerSignVerify, SSAKA)\n");
        goto end;
    }

    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (aka_serverSignVerify, AKA)\n");
        return 0;
    }

    unsigned char *ver = (char *)malloc(sizeof(char) * BUFFER);
    struct ClientProof client;
    struct schnorr_Signature signature;

    init_clientproof(g_globals.keychain->ec_group, &client);
    init_schnorr_signature(g_globals.keychain->ec_group, &signature);

    err = schnorr_sign(g_globals.keychain->ec_group, EC_KEY_get0_private_key(g_serverKeys.keys->keys), Y, EC_POINT_new(g_globals.keychain->ec_group), &signature);
    if (err != 1)
    {
        printf(" * Schnorr signature failed! (shssaka_akaServerSignVerify, SSAKA)\n");
        goto end;
    }

    /*
     *  Server  →   (Y, sigma)      →   Client
     *         (aka_clientProofVerify)
     *  Server  ←   (tau_c, kappa)  ←   Client
     */
    err = shssaka_clientProofVerify(list_of_used_devs, size, Y, &signature, &client);
    if (BN_is_zero(client.tau_c) == 1 || err != 1)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf(" * Client verification failed! (shssaka_akaServerSignVerify, SSAKA)\n");
        goto end;
    }

    BN_copy(client.signature->r, signature.r);
    err = rand_point(g_globals.keychain->ec_group, server->kappa);
    if(err != 1)
    {
        printf(" * Failed to initialize server KAPPA! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }
    sprintf(ver, "%d", schnorr_verify(g_globals.keychain->ec_group, pk_c, Y, server->kappa, client.signature));
    BN_dec2bn(&server->tau_s, ver);

    if (EC_POINT_cmp(g_globals.keychain->ec_group, server->kappa, client.kappa, ctx) == 0)
        printf("\n~ GOOD! :)\n\n");
    else
        err = 0;

end:
    free_clientproof(&client);
    free_schnorr_signature(&signature);
    free(ver);

    return err;
}

unsigned int shssaka_clientProofVerify(unsigned int *list_of_used_devs, unsigned int size, BIGNUM *Y,
                                     struct schnorr_Signature *server_signature, struct ClientProof *client)
{
    unsigned int err = 0;
    unsigned int i = 0;
    EC_POINT *t = EC_POINT_new(g_globals.keychain->ec_group);
    BIGNUM *tmp_mul = BN_new();
    BIGNUM *sk_i = BN_new();
    BIGNUM *sk_0 = BN_new();
    BIGNUM *order = BN_new();
    unsigned char *ver = (char *)malloc(sizeof(char) * BUFFER);
    struct DeviceProof devices[size];
    EC_POINT *t_i[size];
    BIGNUM *r_i[size];
    for (i; i < size; i++)
    {
        init_deviceproof(g_globals.keychain->ec_group, &devices[i]);
        t_i[i] = EC_POINT_new(g_globals.keychain->ec_group);
        r_i[i] = BN_new();
    }

    unsigned int interpolation_list[size + 1];
    interpolation_list[size] = 0;
    for (i = 0; i < size; i++)
    {
        interpolation_list[i] = list_of_used_devs[i];
    }

    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Generation of CTX failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }

    sprintf(ver, "%d", schnorr_verify(g_globals.keychain->ec_group, EC_KEY_get0_public_key(g_serverKeys.keys->keys), Y, EC_POINT_new(g_globals.keychain->ec_group), server_signature));
    BN_dec2bn(&client->tau_c, ver);

    if (BN_is_zero(client->tau_c) == 1)
    {
        printf(" * TAU_C is zero! (shssaka_clientProofVerify, SSAKA)\n");
        return 0;
    }

    err = EC_GROUP_get_order(g_globals.keychain->ec_group, order, ctx);
    if (err != 1)
    {
        printf(" * Get ORDER failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }

    /*  t_s_chck, sk_i  →   SSAKA-DEVICE-PROOFVERIFY(t_s_chck, sk_i)
     *
     *  +++++++++++++++++++++
     *  ++++ DEVICE SIDE ++++
     *  +++++++++++++++++++++
     */

    // for all devices except g_ssakadevicesKeys[0]! --> Client
    for (i = 0; i < size; i++)
    {
        err = rand_range(r_i[i], order);
        if (err != 1)
        {
            printf(" * Generation of random R_I (%d) failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
        err = EC_POINT_mul(g_globals.keychain->ec_group, t_i[i], r_i[i], NULL, NULL, ctx);
        if (err != 1)
        {
            printf(" * Generation of random T_I (%d) failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
        err = EC_POINT_mul(g_globals.keychain->ec_group, devices[i].kappa_i, NULL, server_signature->c_prime, r_i[i], ctx);
        if (err != 1)
        {
            printf(" * Generation of random KAPPA_I (%d) failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
    }

    /*                  ←   <kappa_i, t_i>
     *
     *  +++++++++++++++++++++
     *  ++++ CLIENT SIDE ++++
     *  +++++++++++++++++++++
     */

    err = rand_range(client->signature->r, order);
    if (err != 1)
    {
        printf(" * Generation of random signature R failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }
    
    err = EC_POINT_mul(g_globals.keychain->ec_group, t, client->signature->r, NULL, NULL, ctx);
    if (err != 1)
    {
        printf(" * Computation of prime T failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }
    
    err = EC_POINT_mul(g_globals.keychain->ec_group, client->kappa, NULL, server_signature->c_prime, client->signature->r, ctx);
    if (err != 1)
    {
        printf(" * Computation of prime client's KAPPA failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }
    for (i = 0; i < size; i++)
    {
        err = EC_POINT_add(g_globals.keychain->ec_group, t, t, t_i[i], ctx);
        if (err != 1)
        {
            printf(" * Computation of partial T (%d) failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
        err = EC_POINT_add(g_globals.keychain->ec_group, client->kappa, client->kappa, devices[i].kappa_i, ctx);
        if (err != 1)
        {
            printf(" * Computation of client's KAPPA (%d) failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
    }

    err = ec_hash(g_globals.keychain->ec_group, client->signature->hash, Y, t, client->kappa); // e_c
    if (err != 1)
    {
        printf(" * E_C Hash creation failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }

    /*  e_c             →   SSAKA-DEVICE-PROOFVERIFY
     *
     *  +++++++++++++++++++++
     *  ++++ DEVICE SIDE ++++
     *  +++++++++++++++++++++
     */

    for (i = 0; i < size; i++)
    {
        err = part_interpolation(interpolation_list, size + 1, i, order, sk_i);
        if (err != 1)
        {
            printf(" * %d part interpolation failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
        err = BN_mod_mul(tmp_mul, client->signature->hash, sk_i, order, ctx);
        if (err != 1)
        {
            printf(" * Computation of TMP_MUL (%d) failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
        err = BN_mod_sub(devices[i].s_i, r_i[i], tmp_mul, order, ctx);
        if (err != 1)
        {
            printf(" * Computation of S_I (%d) failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
    }

    /*                  ←   <device_i>
     *
     *  +++++++++++++++++++++
     *  ++++ CLIENT SIDE ++++
     *  +++++++++++++++++++++
     */

    err = part_interpolation(interpolation_list, size + 1, size, order, sk_0);
    if (err != 1)
    {
        printf(" * Client's part interpolation failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }
    err = BN_mod_mul(tmp_mul, client->signature->hash, sk_0, order, ctx);
    if (err != 1)
    {
        printf(" * Computation client's TMP_MUL failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }
    err = BN_mod_sub(client->signature->signature, client->signature->r, tmp_mul, order, ctx);
    if (err != 1)
    {
        printf(" * Computation client's S_I failed! (shssaka_clientProofVerify, SSAKA)\n");
        goto end;
    }

    for (i = 0; i < size; i++)
    {
        err = BN_mod_add(client->signature->signature, client->signature->signature, devices[i].s_i, order, ctx);
        if (err != 1)
        {
            printf(" * Addition of S_I %d failed! (shssaka_clientProofVerify, SSAKA)\n", i);
            goto end;
        }
    }

end:
    EC_POINT_free(t);
    BN_free(tmp_mul);
    BN_free(order);
    BN_free(sk_i);
    BN_free(sk_0);
    free(ver);
    for (i; i < size; i++)
    {
        free_deviceproof(&devices[i]);
        EC_POINT_free(t_i[i]);
        BN_free(r_i[i]);
    }
    BN_CTX_free(ctx);

    return err;
}

void shssaka_keyPrinter(struct shssaka_Keychain *key)
{
    printf("ID: %d\n", key->ID);
    printf("PK: %s\n", BN_bn2dec(key->pk));
    printf("SK: %s\n", BN_bn2dec(key->sk));

    return;
}

unsigned int _get_pk_c()
{
    unsigned int err = 0;
    unsigned int interpolation_list[currentNumberOfDevices];
    BIGNUM *secret = BN_new();
    BIGNUM *order = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (SSAKA, _get_pk_c)\n");
        return 0;
    }

    err = EC_GROUP_get_order(g_globals.keychain->ec_group, order, ctx);
    if (err != 1)
    {
        printf(" * Get order failed! (SSAKA, _get_pk_c)\n");
        goto end;
    }

    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        interpolation_list[i] = i;
    }

    err = paiShamir_interpolation(interpolation_list, currentNumberOfDevices, order, secret);
    if (err != 1)
    {
        printf(" * Shamir interpolation failed! (SSAKA, _get_pk_c)\n");
        goto end;
    }

    err = EC_POINT_mul(g_globals.keychain->ec_group, pk_c, secret, NULL, NULL, ctx);
    if (err != 1)
    {
        printf(" * Computation of PK failed! (SSAKA, _get_pk_c)\n");
        goto end;
    }

end:
    BN_free(secret);
    BN_free(order);
    BN_CTX_free(ctx);

    return err;
}

void init_shssaka_mem()
{
    init_aka_mem(&g_serverKeys);
    if(paillier_inited == 0)
        init_paillier_keychain(&g_paiKeys);
    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        g_shssaka_devicesKeys[i].pk = BN_new();
        g_shssaka_devicesKeys[i].sk = BN_new();
        g_shssaka_devicesKeys[i].kappa = BN_new();
    }
    pk_c = EC_POINT_new(g_globals.keychain->ec_group);

    return;
}

void free_shssaka_mem()
{
    free_aka_mem(&g_serverKeys);
    free_paillier_keychain(&g_paiKeys);
    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        BN_free(g_shssaka_devicesKeys[i].pk);
        BN_free(g_shssaka_devicesKeys[i].sk);
        BN_free(g_shssaka_devicesKeys[i].kappa);
    }
    EC_POINT_free(pk_c);

    return;
}