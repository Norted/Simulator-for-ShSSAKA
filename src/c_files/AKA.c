#include <AKA.h>

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

unsigned int aka_setup()
{
    int i = 0;

    printf("---SERVER---\n");
    init_aka_mem(&g_serverKeys);
    if (!g_serverKeys.ID || !g_serverKeys.keys)
    {
        printf(" * AKA server key initialization failed! (AKA, aka_setup)\n");
        return 0;
    }
    aka_keyPrinter(&g_serverKeys);

    printf("\n---CLIENT---\n");
    init_aka_mem(&g_aka_clientKeys);
    if (!g_aka_clientKeys.ID || !g_aka_clientKeys.keys)
    {
        printf(" * AKA client key initialization failed! (AKA, aka_setup)\n");
        return 0;
    }
    aka_keyPrinter(&g_aka_clientKeys);

    printf("\n");

    return 1;
}

unsigned int aka_serverSignVerify(BIGNUM *Y, struct ServerSign *server)
{
    unsigned int err = 0;

    if (BN_is_zero(Y) == 1 || !g_serverKeys.keys->keys || !g_aka_clientKeys.keys->keys)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf("Y, SERVER sk or CLIENT pk is 0!\n");
        return 0;
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
        printf(" * Schnorr's signature failed! (AKA, aka_serverSignVerify)\n");
        goto end;
    }

    /*
     *  Server  →   (Y, sigma)      →   Client
     *         (aka_clientProofVerify)
     *  Server  ←   (tau_c, kappa)  ←   Client
     */

    err = aka_clientProofVerify(Y, &signature, &client);
    if (err != 1 || BN_is_zero(client.tau_c) == 1)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf(" * Client Proof Verify failed! (AKA, aka_serverSignVerify)\n");
        goto end;
    }

    BN_copy(client.signature->r, signature.r);
    err = rand_point(g_globals.keychain->ec_group, server->kappa);
    if(err != 1)
    {
        printf(" * Failed to initialize server KAPPA! (AKA, aka_clientProofVerify)\n");
        goto end;
    }
    sprintf(ver, "%d", schnorr_verify(g_globals.keychain->ec_group, EC_KEY_get0_public_key(g_aka_clientKeys.keys->keys), Y, server->kappa, client.signature));
    BN_dec2bn(&server->tau_s, ver);

    if (EC_POINT_cmp(g_globals.keychain->ec_group, server->kappa, client.kappa, ctx) == 0)
        printf("\n~ GOOD! :)\n\n");

end:
    free_clientproof(&client);
    free_schnorr_signature(&signature);
    free(ver);
    
    return err;
}

unsigned int aka_clientProofVerify(BIGNUM *Y, struct schnorr_Signature *server_signature, struct ClientProof *client)
{
    unsigned int err = 0;
    unsigned char *ver = (char *)malloc(sizeof(char) * BUFFER);

    sprintf(ver, "%d", schnorr_verify(g_globals.keychain->ec_group, EC_KEY_get0_public_key(g_serverKeys.keys->keys), Y, EC_POINT_new(g_globals.keychain->ec_group), server_signature));
    BN_dec2bn(&client->tau_c, ver);

    if (BN_is_zero(client->tau_c) == 1)
    {
        printf(" * Schnorr's signature verification failed! (AKA, aka_clientProofVerify)\n");
        goto end;
    }

    err = rand_point(g_globals.keychain->ec_group, client->kappa);
    if(err != 1)
    {
        printf(" * Failed to initialize client KAPPA! (AKA, aka_clientProofVerify)\n");
        goto end;
    }
    EC_POINT_copy(client->signature->c_prime, server_signature->c_prime);
    err = schnorr_sign(g_globals.keychain->ec_group, EC_KEY_get0_private_key(g_aka_clientKeys.keys->keys), Y, client->kappa, client->signature);
    if (err != 1)
    {
        printf(" * Client proof verification failed! (AKA, aka_clientProofVerify)\n");
        goto end;
    }

end:
    free(ver);
    return err;
}

void init_aka_mem(struct aka_Keychain *keychain)
{
    keychain->ID = g_globals.idCounter++;
    keychain->keys = (struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));
    gen_schnorr_keychain(g_globals.keychain->ec_group, keychain->keys);
    return;
}

void free_aka_mem(struct aka_Keychain *keychain)
{
    free_schnorr_keychain(keychain->keys);
    free(keychain->keys);
    return;
}

void aka_keyPrinter(struct aka_Keychain *key)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (aka_keyPrinter, AKA)\n");
        return;
    }
    BIGNUM *pk_x = BN_new();
    BIGNUM *pk_y = BN_new();

    if(!EC_POINT_get_affine_coordinates(g_globals.keychain->ec_group, EC_KEY_get0_public_key(key->keys->keys), pk_x, pk_y, ctx))
    {
        printf(" * Failed to get affine coordinates of PK! (aka_keyPrinter, AKA)\n");
        goto end;
    }

    printf("ID: %d\n", key->ID);
    printf("PK: (%s, %s)\n", BN_bn2dec(pk_x), BN_bn2dec(pk_y));
    printf("SK: %s\n", BN_bn2dec(EC_KEY_get0_private_key(key->keys->keys)));

end:
    BN_free(pk_x);
    BN_free(pk_y);
    BN_CTX_free(ctx);

    return;
}