#include <AKA.h>

// definition of global values
struct aka_Keychain g_aka_serverKeys;
struct aka_Keychain g_aka_clientKeys;

// supportive functions declarations
void _aka_keyPrinter(struct aka_Keychain *key);

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
    unsigned int err = 0;
    int i = 0;

    printf("---SERVER---\n");
    err = aka_initKeys(&g_aka_serverKeys);
    if (err != 1)
    {
        printf(" * AKA server key initialization failed! (AKA, aka_setup)\n");
        return 0;
    }
    printf("\n---CLIENT---\n");
    err += aka_initKeys(&g_aka_clientKeys);
    if (err != 1)
    {
        printf(" * AKA client key initialization failed! (AKA, aka_setup)\n");
        return 0;
    }

    printf("\n");

    return 1;
}

// initialize the keychain with computed values
unsigned int aka_initKeys(struct aka_Keychain *keys)
{
    keys->keys = malloc(sizeof(struct schnorr_Keychain));
    unsigned int err = gen_schnorr_keys(keys->keys);
    keys->ID = g_globals.idCounter++;

    _aka_keyPrinter(keys);

    return err;
}

unsigned int aka_serverSignVerify(BIGNUM *Y, struct ServerSign *server)
{
    unsigned int err = 0;
    
    if(BN_is_zero(Y) == 1 || BN_is_zero(g_aka_serverKeys.keys->sk) == 1 || BN_is_zero(g_aka_clientKeys.keys->pk) == 1)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf("Y, SERVER sk or CLIENT pk == 0!\n");
        return 0;
    }

    struct ClientProof client = {{""}};
    client.signature = malloc(sizeof(struct schnorr_Signature));
    struct schnorr_Signature signature = {{""}};
    BN_dec2bn(&server->kappa, "0");

    err = schnorr_sign(g_globals.params, g_aka_serverKeys.keys->sk, Y, server->kappa, &signature);
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
    if (err != 1 || strcmp(client.tau_c, "0") == 0)
    {
        BN_dec2bn(&server->tau_s, "0");
        printf(" * Client Proof Verify failed! (AKA, aka_serverSignVerify)\n");
        goto end;
    }

    BN_copy(client.signature->r, signature.r);
    BN_copy(server->kappa, "1");
    unsigned char *ver = (char *) malloc(BUFFER);
    sprintf(ver, "%d", schnorr_verify(g_globals.params, g_aka_clientKeys.keys->pk, Y, server->kappa, client.signature));
    BN_copy(server->tau_s, ver);

    if (BN_cmp(server->kappa, client.kappa) == 0)
        printf("GOOD! :)\n");

end:
    free(client.signature);
    free(ver);
    return err;
}

unsigned int aka_clientProofVerify(BIGNUM *Y, struct schnorr_Signature *server_signature, struct ClientProof *client)
{
    unsigned int err = 0;
    unsigned char *ver = (char *) malloc(BUFFER);
    sprintf(ver, "%d", schnorr_verify(g_globals.params, g_aka_serverKeys.keys->pk, Y, "0", server_signature));
    BN_dec2bn(&client->tau_c, ver);
    
    if (BN_is_zero(client->tau_c) == 1)
    {
        printf(" * Schnorr's signature verification failed! (AKA, aka_clientProofVerify)\n");
        goto end;
    }

    BN_dec2bn(client->kappa, "1");
    BN_copy(client->signature->c_prime, server_signature->c_prime);
    err = schnorr_sign(g_globals.params, g_aka_clientKeys.keys->sk, Y, client->kappa, client->signature);
    if(err != 1)
    {
        printf(" * Client proof verification failed! (AKA, aka_clientProofVerify)\n");
        goto end;
    }

end:
    free(ver);
    return err;
}

void free_aka_mem()
{
    free(g_globals.params);
    free(g_aka_clientKeys.keys);
    free(g_aka_serverKeys.keys);

    return;
}

/*  Support function definition
 *  print to console the keychain variables
 */

void _aka_keyPrinter(struct aka_Keychain *key)
{
    printf("ID: %d\n", key->ID);
    printf("PK: %s\n", BN_bn2dec(key->keys->pk));
    printf("SK: %s\n", BN_bn2dec(key->keys->sk));

    return;
}