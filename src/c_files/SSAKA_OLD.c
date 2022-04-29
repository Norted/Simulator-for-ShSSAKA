#include <SSAKA_OLD.h>

struct ssaka_Keychain g_ssaka_devicesKeys[G_NUMOFDEVICES];
struct paillier_Keychain g_paiKeys;
BIGNUM *pk_c;

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

unsigned int ssaka_setup()
{
    unsigned int err = 0;
    pk_c = BN_new();
    init_ssaka_mem();

    err = paillier_generate_keypair(&g_paiKeys);
    if (err != 1)
    {
        printf(" * Failed to generate Paillier Keychain! (SSAKA, ssaka_setup)\n");
        goto end;
    }

    printf("---SERVER---\n");
    aka_keyPrinter(&g_serverKeys);
    if (!g_serverKeys.ID)
    {
        printf(" * Initialization of the SSAKA Keys failed! (SSAKA, ssaka_setup)\n");
        goto end;
    }

    int i = 0;
    // pre-init of SSAKA keys for client and other devices
    for (i; i < currentNumberOfDevices; i++)
    {
        err = ssaka_KeyGeneration(&g_ssaka_devicesKeys[i]);
        if (err != 1)
        {
            printf(" * Key generation failed (device %d)! (SSAKA, ssaka_setup)\n", i);
            goto end;
        }
    }

    err = paiShamir_distribution(&g_paiKeys);
    if (err != 1)
    {
        printf(" * Distribution of the secret failed! (SSAKA, ssaka_setup)\n");
        goto end;
    }
    err = _get_pk_c();
    if (err != 1)
    {
        printf(" * Computation of the common PK failed! (SSAKA, ssaka_setup)\n");
        goto end;
    }

    printf("--- CLIENT ---\n");
    ssaka_keyPrinter(&g_ssaka_devicesKeys[0]);

    for (i = 1; i < currentNumberOfDevices; i++)
    {
        printf("--- DEVICE %d ---\n", i);
        ssaka_keyPrinter(&g_ssaka_devicesKeys[i]);
    }

end:
    return err;
}

unsigned int ssaka_KeyGeneration(struct ssaka_Keychain *keys)
{
    keys->keys = (struct schnorr_Keychain*)malloc(sizeof(struct schnorr_Keychain));
    init_schnorr_keychain(keys->keys);
    unsigned int err = rand_range(keys->keys->pk, g_paiKeys.pk->n);
    keys->ID = g_globals.idCounter++;

    return err;
}

unsigned int ssaka_ClientAddShare(unsigned int num_of_new_devices)
{
    unsigned int err = 0;
    if (currentNumberOfDevices + num_of_new_devices > G_NUMOFDEVICES)
    {
        printf("Only %d places left!\n", G_NUMOFDEVICES - currentNumberOfDevices);
        return 2;
    }

    for (int i = 0; i < num_of_new_devices; i++)
    {
        err = ssaka_KeyGeneration(&g_ssaka_devicesKeys[currentNumberOfDevices + i]);
        if (err != 1)
        {
            printf(" * Key generation of device %d filed! (SSAKA, ssaka_ClientAddShare)\n", i);
            goto end;
        }
    }
    currentNumberOfDevices += num_of_new_devices;

    err = paiShamir_distribution(&g_paiKeys);
    if (err != 1)
    {
        printf(" * Distribution of the secret failed! (SSAKA, ssaka_ClientAddShare)\n");
        goto end;
    }
    err = _get_pk_c();
    if (err != 1)
    {
        printf(" * Re-computation of the common PK failed! (SSAKA, ssaka_ClientAddShare)\n");
        goto end;
    }

end:
    return err;
}

unsigned int ssaka_ClientRevShare(unsigned int rev_devices_list[], unsigned int list_size)
{
    int i = 0;
    unsigned int err = 0;
    if (currentNumberOfDevices - list_size < (G_POLYDEGREE + 1))
    {
        printf("Must remain at least %d devices!\n", G_POLYDEGREE + 1);
        return 2;
    }

    for (i; i < list_size; i++)
    {
        if (rev_devices_list[i] == 0)
        {
            printf("Cannot remove client (0)!\n");
            return 3;
        }
        free_schnorr_keychain(g_ssaka_devicesKeys[rev_devices_list[i]].keys);
        free(g_ssaka_devicesKeys[rev_devices_list[i]].keys);
    }

    unsigned int index_list_size = currentNumberOfDevices - list_size;
    unsigned int index_list[index_list_size];
    unsigned int counter = 0;
    for (i = 0; i < currentNumberOfDevices; i++)
    {
        if (g_ssaka_devicesKeys[i].keys != NULL)
        {
            index_list[counter++] = i;
        }
    }

    for (i = 0; i < currentNumberOfDevices; i++)
    {
        if (i < index_list_size)
        {
            g_ssaka_devicesKeys[i].ID = g_ssaka_devicesKeys[index_list[i]].ID;
            g_ssaka_devicesKeys[i].keys = g_ssaka_devicesKeys[index_list[i]].keys;
            BN_copy(g_ssaka_devicesKeys[i].kappa, g_ssaka_devicesKeys[index_list[i]].kappa);
        }
        else
        {
            //g_ssaka_devicesKeys[i].ID = NULL;
            free_schnorr_keychain(g_ssaka_devicesKeys[i].keys);
            free(g_ssaka_devicesKeys[i].keys);
            BN_free(g_ssaka_devicesKeys[i].kappa);
        }
    }

    currentNumberOfDevices -= list_size;
    err = paiShamir_distribution(&g_paiKeys);
    if (err != 1)
    {
        printf(" * Distribution of the secret failed! (SSAKA, ssaka_ClientRevShare)\n");
        goto end;
    }
    err = _get_pk_c();
    if (err != 1)
    {
        printf(" * Re-computation of the common PK failed! (SSAKA, ssaka_ClientRevShare)\n");
        goto end;
    }

end:
    return err;
}

unsigned int ssaka_akaServerSignVerify(unsigned int list_of_used_devs[], unsigned int size, BIGNUM *Y, struct ServerSign *server)
{
    unsigned int err = 0;

    unsigned char *ver = (unsigned char *)malloc(sizeof(unsigned char) * BUFFER);
    struct ClientProof client;
    struct schnorr_Signature signature;
    init_clientproof(&client);
    init_schnorr_signature(&signature);

    BIGNUM *zero = BN_new();
    BN_dec2bn(&zero, "0");

    if (BN_is_zero(Y) == 1 || BN_is_zero(g_serverKeys.keys->sk) == 1 || BN_is_zero(g_ssaka_devicesKeys[0].keys->pk) == 1)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf(" * Y, SERVER sk or CLIENT pk is 0! (SSAKA, ssaka_akaServerSignVerify)\n");
        goto end;
    }

    err = schnorr_sign(g_globals.params, g_serverKeys.keys->sk, Y, zero, &signature);
    if (err != 1)
    {
        printf(" * Create Schnorr signature failed! (SSAKA, ssaka_akaServerSignVerify)\n");
        goto end;
    }

    /*
     *  Server  →   (Y, sigma)      →   Client
     *         (aka_clientProofVerify)
     *  Server  ←   (tau_c, kappa)  ←   Client
     */
    err = ssaka_clientProofVerify(list_of_used_devs, size, Y, &signature, &client);
    if (err != 1 || BN_is_zero(client.tau_c) == 1)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf(" * Client Proof Verify failed! (SSAKA, ssaka_akaServerSignVerify)\n");
        goto end;
    }

    BN_copy(client.signature->r, signature.r);
    BN_dec2bn(&server->kappa, "1");
    printf("** S_kappa: %s\n", BN_bn2dec(server->kappa));
    sprintf(ver, "%d", schnorr_verify(g_globals.params, pk_c, Y, server->kappa, client.signature));
    BN_dec2bn(&server->tau_s, ver);

    if (BN_cmp(server->kappa, client.kappa) == 0)
        printf("\n~ GOOD! :)\n\n");

end:
    free_clientproof(&client);
    free_schnorr_signature(&signature);
    BN_free(zero);
    free(ver);
    return err;
}

unsigned int ssaka_clientProofVerify(unsigned int list_of_used_devs[], unsigned int size, BIGNUM *Y,
                                     struct schnorr_Signature *server_signature, struct ClientProof *client)
{
    unsigned int err = 0;
    int i = 0;

    unsigned char *str_ver = (unsigned char *)malloc(sizeof(unsigned char) * BUFFER);
    unsigned int interpolation_list[size + 1];
    interpolation_list[size] = 0;
    struct DeviceProof devices[size];
    BIGNUM *t_i[size];
    BIGNUM *r_i[size];
    for (i; i < size; i++)
    {
        init_deviceproof(&devices[i]);
        t_i[i] = BN_new();
        r_i[i] = BN_new();
    }
    BIGNUM *t = BN_new();
    BIGNUM *tmp_mul = BN_new();
    BIGNUM *sk_i = BN_new();
    BIGNUM *sk_0 = BN_new();
    BIGNUM *zero = BN_new();
    BN_dec2bn(&zero, "0");
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }

    sprintf(str_ver, "%d", schnorr_verify(g_globals.params, g_serverKeys.keys->pk, Y, zero, server_signature));
    BN_dec2bn(&client->tau_c, str_ver);

    if (BN_is_zero(client->tau_c) == 1)
    {
        printf(" * TAU_C is zero! (SSAKA, ssaka_clientProofVerify)\n");
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
        err = rand_range(r_i[i], g_globals.params->q);
        if (err != 1)
        {
            printf(" * Failed to generate random R for device %d! (SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
        err = BN_mod_exp(t_i[i], g_globals.params->g, r_i[i], g_globals.params->p, ctx);
        if (err != 1)
        {
            printf(" * Computation of G^R_i mod P failed! (%d, SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
        err = BN_mod_exp(devices[i].kappa_i, server_signature->c_prime, r_i[i], g_globals.params->p, ctx);
        if (err != 1)
        {
            printf(" * Computation od devices KAPPA failed! (%d, SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
    }

    /*                  ←   <kappa_i, t_i>
     *
     *  +++++++++++++++++++++
     *  ++++ CLIENT SIDE ++++
     *  +++++++++++++++++++++
     */

    err = rand_range(client->signature->r, g_globals.params->q);
    if (err != 1)
    {
        printf(" * Failed to generate random R for client! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }
    err = BN_mod_exp(t, g_globals.params->g, client->signature->r, g_globals.params->p, ctx);
    if (err != 1)
    {
        printf(" * Computation of G^R mod P failed! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }
    err = BN_mod_exp(client->kappa, server_signature->c_prime, client->signature->r, g_globals.params->p, ctx);
    if (err != 1)
    {
        printf(" * Computation of client KAPPA failed! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }

    for (i = 0; i < size; i++)
    {
        err = BN_mod_mul(t, t, t_i[i], g_globals.params->p, ctx);
        if (err != 1)
        {
            printf(" * Computation of T failed on T_i %d! (SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
        err = BN_mod_mul(client->kappa, client->kappa, devices[i].kappa_i, g_globals.params->p, ctx);
        if (err != 1)
        {
            printf(" * Multiplication of KAPPA with KAPPA_i %d failed! (SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
    }

    err = hash(client->signature->hash, Y, t, client->kappa); // e_c
    if (err != 1)
    {
        printf(" * Hash creation failed! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }

    for (i = 0; i < size; i++)
    {
        interpolation_list[i] = list_of_used_devs[i];
    }

    /*  e_c             →   SSAKA-DEVICE-PROOFVERIFY
     *
     *  +++++++++++++++++++++
     *  ++++ DEVICE SIDE ++++
     *  +++++++++++++++++++++
     */

    for (i = 0; i < size; i++)
    {
        err = part_interpolation(interpolation_list, size + 1, i, sk_i);
        if (err != 1)
        {
            printf(" * %d part of the interpolation failed! (SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
        err = BN_mod_mul(tmp_mul, client->signature->hash, sk_i, g_globals.params->q, ctx);
        if (err != 1)
        {
            printf(" * Multiplication of hash with SK_i failed (%d)! (SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
        err = BN_mod_sub(devices[i].s_i, r_i[i], tmp_mul, g_globals.params->q, ctx);
        if (err != 1)
        {
            printf(" * Reduction of R_i failed (%d)! (SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
    }

    /*                  ←   <device_i>
     *
     *  +++++++++++++++++++++
     *  ++++ CLIENT SIDE ++++
     *  +++++++++++++++++++++
     */

    err = part_interpolation(interpolation_list, size + 1, size, sk_0);
    if (err != 1)
    {
        printf(" * Last part of the interpolation failed! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }
    err = BN_mod_mul(tmp_mul, client->signature->hash, sk_0, g_globals.params->q, ctx);
    if (err != 1)
    {
        printf(" * Multiplication of hash with SK_0 failed! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }
    err = BN_mod_sub(client->signature->signature, client->signature->r, tmp_mul, g_globals.params->q, ctx);
    if (err != 1)
    {
        printf(" * Clients signature computation failed! (SSAKA, ssaka_clientProofVerify)\n");
        goto end;
    }

    for (i = 0; i < size; i++)
    {
        err = BN_mod_add(client->signature->signature, client->signature->signature, devices[i].s_i, g_globals.params->q, ctx);
        if (err != 1)
        {
            printf(" * Extension of clients signature with S_i failed (%d)! (SSAKA, ssaka_clientProofVerify)\n", i);
            goto end;
        }
    }

end:
    for (i = 0; i < size; i++)
    {
        free_deviceproof(&devices[i]);
        BN_free(t_i[i]);
        BN_free(r_i[i]);
    }
    BN_free(t);
    BN_free(tmp_mul);
    BN_free(sk_i);
    BN_free(sk_0);
    BN_free(zero);
    BN_CTX_free(ctx);

    return err;
}

/*  Support function definition
 *  print to console the keychain variables
 */
void ssaka_keyPrinter(struct ssaka_Keychain *key)
{
    printf("ID: %u\n", key->ID);
    printf("PK: %s\n", BN_bn2dec(key->keys->pk));
    printf("SK: %s\n", BN_bn2dec(key->keys->sk));

    return;
}

unsigned int _get_pk_c()
{
    unsigned int err = 0;
    unsigned int interpolation_list[currentNumberOfDevices];
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX! (SSAKA, _get_pk_c)\n");
        return 0;
    }

    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        interpolation_list[i] = i;
    }
    err = paiShamir_interpolation(interpolation_list, currentNumberOfDevices, pk_c);
    if (err != 1)
    {
        printf(" * Shamir interpolation failed! (SSAKA, _get_pk_c)\n");
        goto end;
    }
    err = BN_mod_exp(pk_c, g_globals.params->g, pk_c, g_globals.params->p, ctx);

end:
    BN_CTX_free(ctx);
    return err;
}

void init_ssaka_mem()
{
    init_aka_mem(&g_serverKeys);
    init_paillier_keychain(&g_paiKeys);
    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        g_ssaka_devicesKeys[i].ID = g_globals.idCounter++;
        g_ssaka_devicesKeys[i].keys = (struct schnorr_Keychain *) malloc(sizeof(struct schnorr_Keychain));
        init_schnorr_keychain(g_ssaka_devicesKeys[i].keys);
        g_ssaka_devicesKeys[i].kappa = BN_new();
    }

    return;
}

void free_ssaka_mem()
{
    free_aka_mem(&g_serverKeys);
    free_paillier_keychain(&g_paiKeys);
    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        free_schnorr_keychain(g_ssaka_devicesKeys[i].keys);
        free(g_ssaka_devicesKeys[i].keys);
        BN_free(g_ssaka_devicesKeys[i].kappa);
    }

    return;
}