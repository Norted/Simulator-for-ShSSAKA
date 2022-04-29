#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
// local headers
#include <globals.h>
#include <schnorrs_signature.h>
#include <paillier_scheme.h>
#include <support_functions.h>
#include <paishamir_OLD.h>
#include <AKA.h>
#include <SSAKA_OLD.h>


// Keychains
struct aka_Keychain g_serverKeys;
struct aka_Keychain g_aka_clientKeys;
extern struct ssaka_Keychain g_ssaka_devicesKeys[G_NUMOFDEVICES];

struct paillier_Keychain g_paiKeys;
BIGNUM *pk_c;

// Other globals
struct globals g_globals;
unsigned int currentNumberOfDevices = 4;
DSA *dsa;

unsigned int test_homomorphy();
unsigned int test_paiShamir();

int main(void)
{
    unsigned int return_code = 1;
    unsigned int err = 0;

    /*  AKA-SETUP and AKA-CLIENT-REGISTER
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for devices, client and server side
     */

    /*  AKA test
        BIGNUM * message = BN_new();
        BN_dec2bn(&message, "1234");

        struct ServerSign server;
        init_serversign(&server);

        g_globals.idCounter = 1;
        g_globals.params = malloc(sizeof(struct schnorr_Params));
        if (g_globals.params == NULL)
        {
            printf(" * PARAMS ALOCATION FAILED!\n");
            return_code = 0;
            goto end;
        }
        init_schnorr_params(g_globals.params);
        gen_schnorr_params(g_globals.params);

        err = aka_setup();
        if (err != 1)
        {
            printf(" * AKA setup failed!\n");
            return_code = 0;
            goto end;
        }
        err = aka_serverSignVerify(message, &server);
        if (err != 1)
        {
            printf(" * AKA server sign verify failed!\n");
            return_code = 0;
            goto end;
        }
        printf("ERR:\t%d\nTAU:\t%s\n", err, BN_bn2dec(server.tau_s));

    end:
        printf("\n\nRETURN_CODE: %u\n", return_code);

        free_aka_mem(&g_aka_clientKeys);
        free_aka_mem(&g_serverKeys);
        free_schnorr_params(g_globals.params);
        free(g_globals.params);
        free_serversign(&server);
        BN_free(message);
        free_DSA(dsa);
    */

    /*  SSAKA test  */
        BIGNUM * message = BN_new();
        BN_dec2bn(&message, "1234");

        dsa = DSA_new();

        struct ServerSign server;
        server = *(struct ServerSign *)malloc(sizeof(struct ServerSign));
        init_serversign(&server);

        unsigned int list_of_all_devs[currentNumberOfDevices-1];
        for (int i = 1; i < currentNumberOfDevices; i++) {
            list_of_all_devs[i-1] = i;  //(unsigned int) atoi(g_ssaka_devicesKeys[i].ID);
        }
        unsigned int size_all = sizeof(list_of_all_devs)/sizeof(unsigned int);

        unsigned int list_of_used_devs[] = {1, 2};
        unsigned int size_used = sizeof(list_of_used_devs)/sizeof(unsigned int);

        g_globals.params = (struct schnorr_Params *)malloc(sizeof(struct schnorr_Params));
        if (g_globals.params == NULL)
        {
            printf(" * PARAMS ALOCATION FAILED!\n");
            return_code = 0;
            goto end;
        }
        init_schnorr_params(g_globals.params);
        gen_schnorr_params(dsa, g_globals.params);
        g_globals.idCounter = 1;

        err = ssaka_setup();
        if(err != 1)
        {
            printf(" * SSAKA setup failed!\n");
            return_code = 0;
            goto end;
        }

        /* err = ssaka_ClientAddShare(3);
        if(err != 1)
        {
            printf(" * AddShare failed!\n");
            return_code = 0;
            goto end;
        }
        printf("\n+++ ADDED! +++\n");
        for (int j = 1; j < currentNumberOfDevices; j++) {
            printf("--- DEVICE %d ---\n", j);
            ssaka_keyPrinter(&g_ssaka_devicesKeys[j]);
        }

        unsigned int remove[] = {1, 3};
        unsigned int size_remove = sizeof(remove)/sizeof(unsigned int);
        err = ssaka_ClientRevShare(remove, size_remove);
        if(err != 1)
        {
            printf(" * RevShare failed!\n");
            return_code = 0;
            goto end;
        }

        printf("\n--- REMOVED ---\n");
        for (int j = 1; j < currentNumberOfDevices; j++) {
            printf("--- DEVICE %d ---\n", j);
            ssaka_keyPrinter(&g_ssaka_devicesKeys[j]);
        } */

        err = ssaka_akaServerSignVerify(&list_of_used_devs, size_used, message, &server);
        if(err != 1)
        {
            printf(" * SSAKA Server Sign Verify failed!\n");
            return_code = 0;
            goto end;
        }
        /* err = ssaka_akaServerSignVerify(&list_of_all_devs, size_all, message, &server);
        if(err != 1)
        {
            printf(" * SSAKA Server Sign Verify failed!\n");
            return_code = 0;
            goto end;
        } */

        printf("ERR:\t%d\nTAU:\t%s\n", err, BN_bn2dec(server.tau_s));
    end:
        printf("\n\nRETURN_CODE: %u\n", return_code);

        free_ssaka_mem();
        free_schnorr_params(g_globals.params);
        free(g_globals.params);
        free_serversign(&server);
        BN_free(message);
        DSA_free(dsa);

    //*/

    /*  PAILLIER-SHAMIR test    
    printf("\n\n---PAILLIER-SHAMIR test---\n"); 

    BIGNUM *message = BN_new();
    BN_dec2bn(&message, "1234");
    BIGNUM *message_chck = BN_new();

    dsa = DSA_new();

    unsigned int list_of_used_devs[] = {1, 3, 2};
    unsigned int size_used = sizeof(list_of_used_devs) / sizeof(unsigned int);

    unsigned int list_of_all_devs[currentNumberOfDevices];
    for (unsigned int i = 0; i < currentNumberOfDevices; i++)
    {
        list_of_all_devs[i] = i;
    }
    unsigned int size_all = sizeof(list_of_all_devs) / sizeof(unsigned int);

    g_globals.idCounter = 1;
    g_globals.params = (struct schnorr_Params*)malloc(sizeof(struct schnorr_Params));
    if (g_globals.params == NULL)
    {
        printf(" * PARAMS ALOCATION FAILED!\n");
        return_code = 0;
        goto end;
    }
    init_schnorr_params(g_globals.params);

    struct paillier_Keychain p_keychain;
    init_paillier_keychain(&p_keychain);
    if (&p_keychain.pk == NULL)
    {
        printf(" * Failed to init paillier keychain!\n");
        return_code = 0;
        goto end;
    }

    err = gen_schnorr_params(dsa, g_globals.params);
    if (err != 1)
    {
        printf(" * Failed to generate Schnorr params!\n");
        return_code = 0;
        goto end;
    }

    err = paillier_generate_keypair(&p_keychain);
    if (err != 1)
    {
        printf(" * Failed to generate paillier keys!\n");
        return_code = 0;
        goto end;
    }

    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        g_ssaka_devicesKeys[i].ID = g_globals.idCounter++;
        g_ssaka_devicesKeys[i].keys = (struct schnorr_Keychain *) malloc(sizeof(struct schnorr_Keychain));
        init_schnorr_keychain(g_ssaka_devicesKeys[i].keys);
        g_ssaka_devicesKeys[i].kappa = BN_new();

        err = rand_range(g_ssaka_devicesKeys[i].keys->pk, p_keychain.pk->n);
        if (err != 1)
        {
            printf(" * Generation of a random public key failed!\n");
            return_code = 0;
            goto end;
        }
    }

    err = _shamir_distribution(message);
    //err = paiShamir_distribution(&p_keychain);
    if (err != 1)
    {
        printf(" * Failed to process Shamir's secret distribution!\n");
        return_code = 0;
        goto end;
    }

    /* printf("\n---DEVICES---\n");
    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        printf("\n- DEVICE %d -\n", i);
        ssaka_keyPrinter(&g_ssaka_devicesKeys[i]);
    }
    printf("\n"); //

    err = paiShamir_interpolation(/*list_of_used_devs, size_used, // list_of_all_devs, size_all, message_chck);
    if (err != 1)
    {
        printf(" * Failed to interpolate!\n");
        return_code = 0;
        goto end;
    }

    printf("\nRESULTS:\n|---> MESSAGE: %s\n|---> CHECK: %s\n", BN_bn2dec(message), BN_bn2dec(message_chck));

end:
    printf("\nRETURN CODE: %u\n", return_code);

    BN_free(message);
    BN_free(message_chck);
    free_schnorr_params(g_globals.params);
    free(g_globals.params);
    free_paillier_keychain(&p_keychain);

    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        free_schnorr_keychain(g_ssaka_devicesKeys[i].keys);
        free(g_ssaka_devicesKeys[i].keys);
    }
    
    DSA_free(dsa);
    */

    /*  PAILLIER-SHAMIR test NO#2   
    err = test_paiShamir();
    if(err != 1)
    {
        printf(" * FAIL!\n");
        return err;
    }
    */

    /*  SCHNORR test    
        printf("\n\n---SCHNORR test---\n");
        int stop = 0;

        dsa = DSA_new();
        if(!dsa)
        {
            printf(" * DSA initialization failed!\n");
            return 0;
        }

        struct schnorr_Params params;
        init_schnorr_params(&params);
        struct schnorr_Keychain keys_s;
        init_schnorr_keychain(&keys_s);
        struct schnorr_Signature sign_s;
        init_schnorr_signature(&sign_s);
        struct schnorr_Keychain keys_c;
        init_schnorr_keychain(&keys_c);
        struct schnorr_Signature sign_c;
        init_schnorr_signature(&sign_c);

        BIGNUM *kappa_s = BN_new();
        BN_dec2bn(&kappa_s, "1");
        BIGNUM *kappa_c = BN_new();
        BN_dec2bn(&kappa_c, "1");

        BIGNUM *message = BN_new();
        BN_dec2bn(&message, "1234");

        err = gen_schnorr_params(dsa, &params);
        if(err != 1)
        {
            printf(" * Failed to generate Schnorr parameters!\n");
            return_code = 0;
            goto end;
        }
        printf("--- PARAMETERS ---\nERR: %u\nG: %s\nP: %s\nQ: %s\n", err, BN_bn2dec(params.g), BN_bn2dec(params.p), BN_bn2dec(params.q));
        err = gen_schnorr_keys(dsa, &keys_s);
        if(err != 1)
        {
            printf(" * Failed to generate server's Schnorr keychain!\n");
            return_code = 0;
            goto end;
        }
        printf("\n--- KEYS SERVER --- \nERR: %u\nPK: %s\nSK: %s\n", err, BN_bn2dec(keys_s.pk), BN_bn2dec(keys_s.sk));
        err = gen_schnorr_keys(dsa, &keys_c);
        if(err != 1)
        {
            printf(" * Failed to generate client's Schnorr keychain!\n");
            return_code = 0;
            goto end;
        }
        printf("\n--- KEYS CLIENT--- \nERR: %u\nPK: %s\nSK: %s\n", err, BN_bn2dec(keys_c.pk), BN_bn2dec(keys_c.sk));

        BIGNUM *hash_prime = BN_new();
        BIGNUM *zero = BN_new();
        BN_dec2bn(&zero, "0");

        while(stop <= 10) {
            err = 0;
            BN_dec2bn(&kappa_s, "1");
            BN_dec2bn(&kappa_c, "1");

            printf("\n\n~ TRY N#%d ~\n", stop);
            err = schnorr_sign(&params, keys_s.sk, message, zero, &sign_s);
            if(err != 1)
            {
                printf(" * Schnorr server signin failed!\n");
                return_code = 0;
                goto end;
            }
            BN_copy(hash_prime, sign_s.hash);
            printf("\n--- SIGNATURE SERVER ---\nERR: %u\nSIGNATURE: %s\nHASH: %s\n", err, BN_bn2dec(sign_s.signature), BN_bn2dec(sign_s.hash));
            err = schnorr_verify(&params, keys_s.pk, message, zero, &sign_s);
            if(err != 1)
            {
                printf(" * Schnorr server signature verification failed!\n");
                return_code = 0;
                goto end;
            }
            else
            {
                printf(" * Verification proceeded! :)\n");
            }

            BN_copy(sign_c.c_prime, sign_s.c_prime);
            err = schnorr_sign(&params, keys_c.sk, message, kappa_c, &sign_c);
            if(err != 1)
            {
                printf(" * Schnorr client signin failed!\n");
                return_code = 0;
                goto end;
            }
            printf("\n--- SIGNATURE CLIENT ---\nERR: %u\nSIGNATURE: %s\nHASH: %s\n\nKAPPA_C: %s\n", err, BN_bn2dec(sign_c.signature), BN_bn2dec(sign_c.hash), BN_bn2dec(kappa_c));

            BN_copy(sign_c.r, sign_s.r);
            err = schnorr_verify(&params, keys_c.pk, message, kappa_s, &sign_c);
            printf("KAPPA_S: %s\n", BN_bn2dec(kappa_s));
            if(BN_cmp(kappa_c, kappa_s) != 0)
            {
                printf(" * Schnorr client signature verification failed!\n");
                return_code = 0;
                goto end;
            }
            else
            {
                printf(" * Verification proceeded! :)\n");
            }
            stop ++;
        }

    end:
        printf("\n\nRETURN_CODE: %u\n", return_code);

        DSA_free(dsa);
        free_schnorr_params(&params);
        free_schnorr_keychain(&keys_c);
        free_schnorr_keychain(&keys_s);
        free_schnorr_signature(&sign_c);
        free_schnorr_signature(&sign_s);
        BN_free(kappa_c);
        BN_free(kappa_s);
        BN_free(hash_prime);
        BN_free(zero);
    */

    /*  PAILLIER test
        printf("\n\n---PAILLIER test---\n");

        BIGNUM *message = BN_new();
        BN_dec2bn(&message, "125");
        BIGNUM *enc = BN_new();
        BIGNUM *dec = BN_new();

        BIGNUM *zero1 = BN_new();
        BIGNUM *zero2 = BN_new();
        BN_dec2bn(&zero1, "0");
        BN_dec2bn(&zero2, "0");

        struct paillier_Keychain p_keyring;
        init_paillier_keychain(&p_keyring);
        if(&p_keyring == NULL)
        {
            printf(" * Failed to init PAILLIER KEYCHAIN!\n");
            return_code = 0;
            goto end;
        }

        // INIT KEYS
        err = paillier_generate_keypair(&p_keyring);
        if(err != 1)
        {
            printf(" * Failed to generate Paillier Keypair!\n");
            return_code = 0;
            goto end;
        }
        printf("ERR: %u\nKEYS:\n|--> L: %s\n|--> MI: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n", err, BN_bn2dec(p_keyring.sk->lambda),
            BN_bn2dec(p_keyring.sk->mi), BN_bn2dec(p_keyring.pk->n), BN_bn2dec(p_keyring.pk->n_sq), BN_bn2dec(p_keyring.pk->g));
        printf("\n\nSECRET: %s\n", BN_bn2dec(message));

        // ENCRYPTION
        err = paillier_encrypt(p_keyring.pk, message, enc, zero1, zero2);
        if(err != 1)
        {
            printf(" * Failed to process the encryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        printf("ENC: %s\n", BN_bn2dec(enc));

        // DECRYPTION
        err = paillier_decrypt(&p_keyring, enc, dec);
        if(err != 1)
        {
            printf(" * Failed to process the decryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        printf("DEC: %s\n", BN_bn2dec(dec));

        printf("\n\n---PAILLIER HOMOMORPHY test---\n");
        err = test_homomorphy();
        if(err != 1)
        {
            printf(" * Homomorphy test failed!\n");
            return_code = 0;
        }

    end:
        printf("\n\nRETURN_CODE: %u\n", return_code);

        free_paillier_keychain(&p_keyring);
        BN_free(message);
        BN_free(enc);
        BN_free(dec);
        BN_free(zero1);
        BN_free(zero2);
    */

    return return_code;
}

// HOMOMORPHY test for PAILLIER SCHEME
unsigned int test_homomorphy()
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Falied to generate CTX! (scheme 1, generate keypair)\n");
        return err;
    }

    BIGNUM *zero1 = BN_new();
    BIGNUM *zero2 = BN_new();
    BIGNUM *message_1 = BN_new();
    BIGNUM *message_2 = BN_new();
    BIGNUM *message_sum = BN_new();
    BIGNUM *message_mul = BN_new();
    BIGNUM *cipher_1 = BN_new();
    BIGNUM *cipher_2 = BN_new();
    BIGNUM *cipher_sum_1 = BN_new();
    BIGNUM *dec_cipher_sum_1 = BN_new();
    BIGNUM *cipher_sum_2 = BN_new();
    BIGNUM *dec_cipher_sum_2 = BN_new();
    BIGNUM *cipher_mul = BN_new();
    BIGNUM *dec_cipher_mul = BN_new();

    struct paillier_Keychain keychain;
    init_paillier_keychain(&keychain);

    err = paillier_generate_keypair(&keychain);
    if (err != 1)
    {
        printf(" * Generate keychain failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    BN_dec2bn(&zero1, "0");
    BN_dec2bn(&zero2, "0");
    BN_dec2bn(&message_1, "100");
    BN_dec2bn(&message_2, "50");

    err = BN_add(message_sum, message_1, message_2);
    if (err != 1)
    {
        printf(" * Add plaintexts failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = BN_mul(message_mul, message_1, message_2, ctx);
    if (err != 1)
    {
        printf(" * Mul plaintexts falied (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = paillier_encrypt(keychain.pk, message_1, cipher_1, zero1, zero2);
    if (err != 1)
    {
        printf(" * Message 1 encryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    BN_dec2bn(&zero1, "0");
    BN_dec2bn(&zero2, "0");

    err = paillier_encrypt(keychain.pk, message_2, cipher_2, zero1, zero2);
    if (err != 1)
    {
        printf(" * Message 2 encryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = homomorphy_add(keychain.pk, cipher_1, cipher_2, cipher_sum_1);
    if (err != 1)
    {
        printf(" * Add ciphertexts failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = paillier_decrypt(&keychain, cipher_sum_1, dec_cipher_sum_1);
    if (err != 1)
    {
        printf(" * Added ciphertext decryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = homomorphy_add_const(keychain.pk, cipher_1, message_2, cipher_sum_2);
    if (err != 1)
    {
        printf(" * Add constant failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = paillier_decrypt(&keychain, cipher_sum_2, dec_cipher_sum_2);
    if (err != 1)
    {
        printf(" * Add ciphertext wih constant decryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    err = homomorphy_mul_const(keychain.pk, cipher_1, message_2, cipher_mul);
    if (err != 1)
    {
        printf(" * Mul const failed (scheme 1, homomorphy)!\n");
        goto end;
    }
    err = paillier_decrypt(&keychain, cipher_mul, dec_cipher_mul);
    if (err != 1)
    {
        printf(" * Mul ciphertext with const decryption failed (scheme 1, homomorphy)!\n");
        goto end;
    }

    printf("|--> MESSAGE 1: %s\n|--> MESSAGE 2: %s\n", BN_bn2dec(message_1), BN_bn2dec(message_2));
    printf("|--> MESSAGE SUM: %s\n|--> MESSAGE MUL: %s\n\n", BN_bn2dec(message_sum), BN_bn2dec(message_mul));
    printf("|--> CIPHER SUM 1: %s\n|--> CIPHER SUM 2: %s\n", BN_bn2dec(dec_cipher_sum_1), BN_bn2dec(dec_cipher_sum_2));
    printf("|--> CIPHER MUL: %s\n", BN_bn2dec(dec_cipher_mul));

end:
    BN_free(zero1);
    BN_free(zero2);
    BN_free(message_1);
    BN_free(message_2);
    BN_free(message_sum);
    BN_free(message_mul);
    BN_free(cipher_1);
    BN_free(cipher_2);
    BN_free(cipher_sum_1);
    BN_free(cipher_sum_2);
    BN_free(dec_cipher_sum_1);
    BN_free(dec_cipher_sum_2);
    BN_free(cipher_mul);
    BN_free(dec_cipher_mul);
    BN_CTX_free(ctx);

    free_paillier_keychain(&keychain);

    return err;
}

unsigned int test_paiShamir()
{
    unsigned int err = 0;

    struct schnorr_Params params;
    params = *(struct schnorr_Params *)malloc(sizeof(struct schnorr_Params));
    init_schnorr_params(&params);
    struct schnorr_Keychain keys_server;
    keys_server = *(struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));
    init_schnorr_keychain(&keys_server);
    struct schnorr_Keychain keys_client;
    keys_client = *(struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));
    init_schnorr_keychain(&keys_client);
    struct schnorr_Keychain keys_device1;
    keys_device1 = *(struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));
    init_schnorr_keychain(&keys_device1);
    struct schnorr_Keychain keys_device2;
    keys_device2 = *(struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));
    init_schnorr_keychain(&keys_device2);

    struct paillier_Keychain paikeys;
    init_paillier_keychain(&paikeys);

    dsa = DSA_new();

    BIGNUM *SUM = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *ci = BN_new();
    BIGNUM *cN_prime = BN_new();
    BIGNUM *sk_sum = BN_new();
    BIGNUM *pk = BN_new();
    BIGNUM *pk_ch = BN_new();
    BIGNUM *r_s = BN_new();
    BIGNUM *t_s = BN_new();
    BIGNUM *e_s = BN_new();
    BIGNUM *Y = BN_new();
    BN_dec2bn(&Y, "1234");
    BIGNUM *zero = BN_new();
    BN_dec2bn(&zero, "0");
    BIGNUM *s_s = BN_new();
    BIGNUM *s_s_mul = BN_new();
    BIGNUM *t_s_ch = BN_new();
    BIGNUM *ch_1 = BN_new();
    BIGNUM *ch_2 = BN_new();
    BIGNUM *e_s_ch = BN_new();
    BIGNUM *r_c = BN_new();
    BIGNUM *t_c = BN_new();
    BIGNUM *kappa_c = BN_new();
    BIGNUM *e_c = BN_new();
    BIGNUM *sub = BN_new();
    BIGNUM *inv = BN_new();
    BIGNUM *mul = BN_new();
    BIGNUM *si_sum = BN_new();
    BIGNUM *sc_inter = BN_new();
    BIGNUM *s_c = BN_new();
    BIGNUM *s_c_mul = BN_new();
    BIGNUM *t_ch = BN_new();
    BIGNUM *tch_1 = BN_new();
    BIGNUM *tch_2 = BN_new();
    BIGNUM *kappa_s = BN_new();
    BIGNUM *e_c_ch = BN_new();
    BIGNUM *r_i[2];
    BIGNUM *t_i[2];
    BIGNUM *kappa_i[2];
    BIGNUM *s_i[2];
    for(int i = 0; i < 2; i++)
    {
        r_i[i] = BN_new();
        t_i[i] = BN_new();
        kappa_i[i] = BN_new();
        s_i[i] = BN_new();
    }
    BIGNUM *kappa_inter[3];
    for(int i = 0; i < 3; i++)
    {
        kappa_inter[i] = BN_new();
    }
    BIGNUM *d[3][G_POLYDEGREE];
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            d[i][j] = BN_new();
        }
    }
    BN_CTX *ctx = BN_CTX_secure_new();
    if(ctx == NULL)
    {
        printf(" * Failed to generate CTX! (test_paiShamir, main)\n");
        goto end;
    }
    

    err = gen_schnorr_params(dsa, &params);
    if(err != 1)
    {
        printf(" * Failed to generate Schnorr Params! (test_paiShamir, main)\n");
        goto end;
    }
    err = gen_schnorr_keys(dsa, &keys_server);
    if(err != 1)
    {
        printf(" * Failed to generate server Schnorr Keychain! (test_paiShamir, main)\n");
        goto end;
    }
    err = gen_schnorr_keys(dsa, &keys_client);
    if(err != 1)
    {
        printf(" * Failed to generate client Schnorr Keychain! (test_paiShamir, main)\n");
        goto end;
    }
    err = gen_schnorr_keys(dsa, &keys_device1);
    if(err != 1)
    {
        printf(" * Failed to generate device 1 Schnorr Keychain! (test_paiShamir, main)\n");
        goto end;
    }
    err = gen_schnorr_keys(dsa, &keys_device2);
    if(err != 1)
    {
        printf(" * Failed to generate device 2 Schnorr Keychain! (test_paiShamir, main)\n");
        goto end;
    }


    err = paillier_generate_keypair(&paikeys);
    if(err != 1)
    {
        printf(" * Failed to generate Paillier Keychain! (test_paiShamir, main)\n");
        goto end;
    }

    for (int i = 0; i < 3; i++) {
        err = rand_range(kappa_inter[i], paikeys.pk->n);
        if(err != 1)
        {
            printf(" * Generate random KAPPA_INTER %d failed! (test_paiShamir, main)\n", i);
            goto end;
        }
        err = BN_add(SUM, kappa_inter[i], SUM);
        if(err != 1)
        {
            printf(" * Failed to add KAPPA_INTER %d to SUM! (test_paiShamir, main)\n", i);
            goto end;
        }
        for(int j = 0; j < G_POLYDEGREE; j++) {
            err = rand_range(d[i][j], paikeys.pk->n);
            if(err != 1)
            {
                printf(" * Generate random D %d-%d failed! (test_paiShamir, main)\n", i, j);
                goto end;
            }
        }
    }
    printf("\n");
    
    // SHARE
    err = paiShamir_get_ci(&paikeys, kappa_inter[0], d[0], keys_client.pk, c);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_ci(&paikeys, kappa_inter[1], d[1], keys_client.pk, cN_prime);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_ci(&paikeys, kappa_inter[2], d[2], keys_client.pk, ci);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #3 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_cN_prime(&paikeys, cN_prime, ci, cN_prime);
    if(err != 1)
    {
        printf(" * paiShamir_get_cN_prime #1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_share(&paikeys, cN_prime, c, keys_client.sk);
    if(err != 1)
    {
        printf(" * paiShamir_get_share #1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    printf("SK_C: %s\n", BN_bn2dec(keys_client.sk));


    err = paiShamir_get_ci(&paikeys, kappa_inter[1], d[1], keys_device1.pk, c);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #4 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_ci(&paikeys, kappa_inter[2], d[2], keys_device1.pk, cN_prime);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #5 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_ci(&paikeys, kappa_inter[0], d[0], keys_device1.pk, ci);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #6 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_cN_prime(&paikeys, cN_prime, ci, cN_prime);
    if(err != 1)
    {
        printf(" * paiShamir_get_cN_prime #2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_share(&paikeys, cN_prime, c, keys_device1.sk);
    if(err != 1)
    {
        printf(" * paiShamir_get_share #2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    printf("SK_1: %s\n", BN_bn2dec(keys_device1.sk));


    err = paiShamir_get_ci(&paikeys, kappa_inter[2], d[2], keys_device2.pk, c);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #7 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_ci(&paikeys, kappa_inter[0], d[0], keys_device2.pk, cN_prime);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #8 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_ci(&paikeys, kappa_inter[1], d[1], keys_device2.pk, ci);
    if(err != 1)
    {
        printf(" * paiShamir_get_ci #9 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_cN_prime(&paikeys, cN_prime, ci, cN_prime);
    if(err != 1)
    {
        printf(" * paiShamir_get_cN_prime #3 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = paiShamir_get_share(&paikeys, cN_prime, c, keys_device2.sk);
    if(err != 1)
    {
        printf(" * paiShamir_get_share #3 failed! (test_paiShamir, main)\n");
        goto end;
    }
    printf("SK_2: %s\n", BN_bn2dec(keys_device2.sk));

    
    printf("\nKappa_SUM: %s\n", BN_bn2dec(SUM));
    err = BN_mod_exp(SUM, params.g, SUM, params.p, ctx);
    if(err != 1)
    {
        printf(" * Failed to compute KAPPA_PK! (test_paiShamir, main)\n");
        goto end;
    }
    printf("\nKappa_PK: %s\n\n", BN_bn2dec(SUM));


    BN_copy(sk_sum, kappa_inter[0]);
    err = BN_add(sk_sum, kappa_inter[1], sk_sum);
    if(err != 1)
    {
        printf(" * Addition of KAPPA_INTER 1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_add(sk_sum, kappa_inter[2], sk_sum);
    if(err != 1)
    {
        printf(" * Addition of KAPPA_INTER 2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    printf("SK_C: %s\nSK_D1: %s\nSK_D2: %s\nSK_SUM: %s\n\n", BN_bn2dec(kappa_inter[0]), BN_bn2dec(kappa_inter[1]), BN_bn2dec(kappa_inter[2]), BN_bn2dec(sk_sum));
    

    BN_copy(pk, keys_client.pk);
    err = BN_mul(pk, keys_device1.pk, pk, ctx);
    if(err != 1)
    {
        printf(" * Multiplication of PK 1 to PK failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mul(pk, keys_device2.pk, pk, ctx);
    if(err != 1)
    {
        printf(" * Multiplication of PK 2 to PK failed! (test_paiShamir, main)\n");
        goto end;
    }

    err = BN_mod_exp(pk_ch, params.g, sk_sum, params.p, ctx);
    if(err != 1)
    {
        printf(" * Creation of PK_CH failed! (test_paiShamir, main)\n");
        goto end;
    }
    printf("PK: %s\nPK_CH: %s\n\n", BN_bn2dec(pk), BN_bn2dec(pk_ch));
    

    err = rand_range(r_s, params.q);
    if(err != 1)
    {
        printf(" * Generation of random R_S failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_exp(t_s, params.g, r_s, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of T_S failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = hash(e_s, Y, t_s, zero);
    if(err != 1)
    {
        printf(" * E_S Hash creation failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(s_s_mul, e_s, keys_server.sk, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_S_MUL failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_sub(s_s, r_s, s_s_mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_S failed! (test_paiShamir, main)\n");
        goto end;
    }

    //--------------------------
    
    err = BN_mod_exp(ch_1, params.g, s_s, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of CH_1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_exp(ch_2, keys_server.pk, e_s, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of CH_2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(t_s_ch, ch_1, ch_2, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of T_S_CH failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = hash(e_s_ch, Y, t_s_ch, zero);
    if(err != 1)
    {
        printf(" * E_S_CH Hash creation failed! (test_paiShamir, main)\n");
        goto end;
    }
    int tau_c = BN_cmp(e_s, e_s_ch);
    printf("TAU_C: %d (if 0 --> OK!)\n", tau_c);


    err = rand_range(r_c, params.q);
    if(err != 1)
    {
        printf(" * Generation of random R_C failed! (test_paiShamir, main)\n");
        goto end;
    }

    for(int i = 0; i < 2; i++) {
        err = rand_range(r_i[i], params.q);
        if(err != 1)
        {
            printf(" * Generation of a random R_I %d failed! (test_paiShamir, main)\n", i);
            goto end;
        }
        err = BN_mod_exp(t_i[i], params.g, r_i[i], params.p, ctx);
        if(err != 1)
        {
            printf(" * Computation of T_I %d failed! (test_paiShamir, main)\n", i);
            goto end;
        }
        err = BN_mod_exp(kappa_i[i], t_s_ch, r_i[i], params.p, ctx);
        if(err != 1)
        {
            printf(" * Computation of KAPPA_I %d failed! (test_paiShamir, main)\n", i);
            goto end;
        }
    }


    err = BN_mod_exp(t_c, params.g, r_c, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of T_C failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_exp(kappa_c, t_s_ch, r_c, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of KAPPA_C failed! (test_paiShamir, main)\n");
        goto end;
    }
    for(int i = 0; i < 2; i++) {
        err = BN_mod_mul(t_c, t_c, t_i[i], params.p, ctx);
        if(err != 1)
        {
            printf(" * Computation of T_C failed in I = %d! (test_paiShamir, main)\n", i);
            goto end;
        }
        err = BN_mod_mul(kappa_c, kappa_c, kappa_i[i], params.p, ctx);
        if(err != 1)
        {
            printf(" * Computation of KAPPA_C failed in I = %d! (test_paiShamir, main)\n", i);
            goto end;
        }
    }
    err = hash(e_c, Y, t_c, kappa_c);
    if(err != 1)
    {
        printf(" * E_C Hash creation failed! (test_paiShamir, main)\n");
        goto end;
    }
    BN_copy(s_i[0], keys_device1.sk);
    err = BN_mod_sub(sub, keys_device2.pk, keys_device1.pk, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computationof SUB #1, failed! (test_paiShamir, main)\n");
        goto end;
    }
    if(!BN_mod_inverse(inv, sub, params.q, ctx))
    {
        printf(" * Computation fo IVN #1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(mul, keys_device2.pk, inv, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of MUL #1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(s_i[0], s_i[0], mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_I 0 #1 failed! (test_paiShamin, main)\n");
        goto end;
    }
    err = BN_mod_sub(sub, keys_client.pk, keys_device1.pk, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of SUB #2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    if(!BN_mod_inverse(inv, sub, params.q, ctx))
    {
        printf(" * Computation fo INV #2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(mul, keys_client.pk, inv, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of MUL #2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(s_i[0], s_i[0], mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_I 0 #2 failed! (test_paiShamin, main)\n");
        goto end;
    }
    
    BN_copy(s_i[1], keys_device2.sk);
    err = BN_mod_sub(sub, keys_device1.pk, keys_device2.pk, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computationof SUB #3, failed! (test_paiShamir, main)\n");
        goto end;
    }
    if(!BN_mod_inverse(inv, sub, params.q, ctx))
    if(err != 1)
    {
        printf(" * Computation of INV #3 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(mul, keys_device1.pk, inv, params.q, ctx);
    if(err != 1)
    {
        printf(" * Compuation of MUL #3 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(s_i[1], s_i[1], mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_I 0 #1 failed! (test_paiShamin, main)\n");
        goto end;
    }
    err = BN_mod_sub(sub, keys_client.pk, keys_device2.pk, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computationof SUB #4, failed! (test_paiShamir, main)\n");
        goto end;
    }
    if(!BN_mod_inverse(inv, sub, params.q, ctx))
    if(err != 1)
    {
        printf(" * Computation of INV #4 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(mul, keys_client.pk, inv, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computationof MUL #4 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(s_i[1], s_i[1], mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_I 0 #2 failed! (test_paiShamin, main)\n");
        goto end;
    }


    BN_copy(si_sum, s_i[0]);
    err = BN_mod_add(si_sum, si_sum, s_i[1], params.q, ctx);
    if(err != 1)
    {
        printf(" * Addition of S_I 1 to SI_SUM failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(s_i[0], e_c, s_i[0], params.q, ctx);
    if(err != 1)
    {
        printf(" * Multiplication of S_I O and E_C failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(s_i[1], e_c, s_i[1], params.q, ctx);
    if(err != 1)
    {
        printf(" * Multiplication of S_I 1 and E_C failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_sub(s_i[0], r_i[0], s_i[0], params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_I 0 (sub R_I 0) failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_sub(s_i[1], r_i[1], s_i[1], params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_I 1 (sub R_I 1) failed! (test_paiShamir, main)\n");
        goto end;
    }


    BN_copy(sc_inter, keys_client.sk);
    err = BN_mod_sub(sub, keys_device1.pk, keys_client.pk, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of SUB #5 failed! (test_paiShamir, main)\n");
        goto end;
    }
    if(!BN_mod_inverse(inv, sub, params.q, ctx))
    {
        printf(" * Computation of INV #5 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(mul, keys_device1.pk, inv, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of MUL #5 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(sc_inter, sc_inter, mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of SC_INTER #1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_sub(sub, keys_device2.pk, keys_client.pk, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation fo SUB #6 failed! (test_paiShamir, main)\n");
        goto end;
    }
    if(!BN_mod_inverse(inv, sub, params.q, ctx))
    if(err != 1)
    {
        printf(" * Computation of INV #6 failed! (tets_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(mul, keys_device2.pk, inv, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of MUL #6 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(sc_inter, sc_inter, mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of SC_INTER #2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_add(si_sum, si_sum, sc_inter, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of SI_SUM faild! (test_paiShamir, main)\n");
        goto end;
    }
    printf("SI_SUM: %s\n", BN_bn2dec(si_sum));

    err = BN_mod_mul(s_c_mul, e_c, sc_inter, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_C_MUL failed! (tets_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_sub(s_c, r_c, s_c_mul, params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_C failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_add(s_c, s_c, s_i[0], params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_C #1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_add(s_c, s_c, s_i[1], params.q, ctx);
    if(err != 1)
    {
        printf(" * Computation of S_C #2 failed! (test_paiShamir, main)\n");
        goto end;
    }


    //--------------------------
    err = BN_mod_exp(tch_1, params.g, s_c, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of TCH_1 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_exp(tch_2, pk, e_c, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of TCH_2 failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_mul(t_ch, tch_1, tch_2, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of T_CH failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = BN_mod_exp(kappa_s, t_ch, r_s, params.p, ctx);
    if(err != 1)
    {
        printf(" * Computation of KAPPA_S failed! (test_paiShamir, main)\n");
        goto end;
    }
    err = hash(e_c_ch, Y, t_ch, kappa_s);
    if(err != 1)
    {
        printf(" * E_C_CH Hash creation failed! (test_paiShamir, main)\n");
        goto end;
    }
    int tau_s = BN_cmp(e_c, e_c_ch);
    printf("TAU_S: %d (if 0 --> OK!)\nE_C: %s\nE_C_CH: %s\n", tau_s, BN_bn2dec(e_c), BN_bn2dec(e_c_ch));
    
end:
    free_schnorr_params(&params);
    free_schnorr_keychain(&keys_server);
    free_schnorr_keychain(&keys_client);
    free_schnorr_keychain(&keys_device1);
    free_schnorr_keychain(&keys_device2);
    free_paillier_keychain(&paikeys);

    BN_free(SUM);
    BN_free(c);
    BN_free(ci);
    BN_free(cN_prime);
    BN_free(sk_sum);
    BN_free(pk);
    BN_free(pk_ch);
    BN_free(r_s);
    BN_free(t_s);
    BN_free(e_s);
    BN_free(Y);
    BN_free(zero);
    BN_free(s_s);
    BN_free(s_s_mul);
    BN_free(t_s_ch);
    BN_free(ch_1);
    BN_free(ch_2);
    BN_free(e_s_ch);
    BN_free(r_c);
    BN_free(t_c);
    BN_free(kappa_c);
    BN_free(e_c);
    BN_free(sub);
    BN_free(inv);
    BN_free(mul);
    BN_free(si_sum);
    BN_free(sc_inter);
    BN_free(s_c);
    BN_free(s_c_mul);
    BN_free(t_ch);
    BN_free(tch_1);
    BN_free(tch_2);
    BN_free(kappa_s);
    BN_free(e_c_ch);

    for(int i = 0; i < 2; i++)
    {
        BN_free(r_i[i]);
        BN_free(t_i[i]);
        BN_free(kappa_i[i]);
        BN_free(s_i[i]);
    }
    for(int i = 0; i < 3; i++)
    {
        BN_free(kappa_inter[i]);
    }
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < G_POLYDEGREE; j++)
        {
            BN_free(d[i][j]);
        }
    }

    DSA_free(dsa);

    return err;
}


/* --- RESOURCES ---
 *  https://math.stackexchange.com/questions/814879/find-a-generator-of-the-multiplicative-group-of-mathbbz-23-mathbbz-as-a-c
 *  https://stackoverflow.com/questions/23360728/how-to-generate-a-number-of-n-bit-in-length
 */