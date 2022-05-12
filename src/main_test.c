#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
// local headers
#include <globals.h>
#include <schnorrs_signature.h>
#include <paillier_scheme.h>
#include <support_functions.h>
#include <paishamir.h>
#include <AKA.h>
#include <SSAKA.h>

// Keychains
struct aka_Keychain g_serverKeys;
struct aka_Keychain g_aka_clientKeys;
extern struct ssaka_Keychain g_ssaka_devicesKeys[G_NUMOFDEVICES];

struct paillier_Keychain g_paiKeys;
EC_POINT *pk_c;

// Globals
BIGNUM *g_range;
struct globals g_globals;
unsigned int currentNumberOfDevices = 4;

// Threding and pre-computation globals
unsigned int paillier_inited = 0;
unsigned int pre_noise = 0;
unsigned int pre_message = 0;

// File names
const char *restrict file_keychain = "keychain.json";
const char *restrict file_precomputed_noise = "precomputed_values/precomputation_noise.json";
const char *restrict file_precomputed_message = "precomputed_values/precomputation_message.json";

unsigned int test_homomorphy();
unsigned int test_paiShamir();

int main(void)
{
    unsigned int return_code = 1;
    unsigned int err = 0;

    BIGNUM *message = BN_new();
    BN_dec2bn(&message, "123");

    g_globals.idCounter = 1;
    g_globals.keychain = (struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));

    unsigned char *tmp_str = (char *)malloc(sizeof(char) * BUFFER);
    g_range = BN_new();
    sprintf(tmp_str, "%d", RANGE);
    BN_dec2bn(&g_range, tmp_str);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL)
    {
        printf(" * Failed to generate EC group!\n");
        return_code = 0;
        // goto final;
    }
    if (g_globals.keychain == NULL)
    {
        printf(" * KEYCHAIN ALOCATION FAILED!\n");
        return_code = 0;
        // goto final;
    }
    err = gen_schnorr_keychain(group, g_globals.keychain);
    if (err != 1)
    {
        printf(" * Failed to generate Schnorr params!\n");
        return_code = 0;
        // goto final;
    }

    /*  AKA-SETUP and AKA-CLIENT-REGISTER
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for devices, client and server side
     */

    /*  AKA test
        printf("\n\n---AKA test---\n");
        struct ServerSign server;
        init_serversign(g_globals.keychain->ec_group, &server);

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
        free_schnorr_keychain(g_globals.keychain);
        free(g_globals.keychain);
        free_serversign(&server);
    //*/

    /*  SSAKA test  */
    printf("\n\n---SSAKA test---\n");

    unsigned int list_of_all_devs[currentNumberOfDevices - 1];
    for (int i = 1; i < currentNumberOfDevices; i++)
    {
        list_of_all_devs[i - 1] = i;
    }
    unsigned int size_all = sizeof(list_of_all_devs) / sizeof(unsigned int);

    unsigned int list_of_used_devs[] = {1, 2};
    unsigned int size_used = sizeof(list_of_used_devs) / sizeof(unsigned int);

    struct ServerSign server;
    init_serversign(g_globals.keychain->ec_group, &server);

    pre_message = 1;
    pre_noise = 1;
    
    err = ssaka_setup();
    if (err != 1)
    {
        printf(" * SSAKA setup failed!\n");
        return_code = 0;
        goto end;
    }

    err = ssaka_ClientAddShare(3);
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
    }

    /* err = ssaka_akaServerSignVerify(list_of_all_devs, size_all, message, &server);
    if(err != 1)
    {
        printf(" * SSAKA Server Sign Verify failed!\n");
        return_code = 0;
        goto end;
    }

    printf("ERR:\t%d\nTAU:\t%s\n", err, BN_bn2dec(server.tau_s)); */

    err = ssaka_akaServerSignVerify(list_of_used_devs, size_used, message, &server);
    if (err != 1)
    {
        printf(" * SSAKA Server Sign Verify failed!\n");
        return_code = 0;
        goto end;
    }

    printf("ERR:\t%d\nTAU:\t%s\n", err, BN_bn2dec(server.tau_s));

end:
    printf("\n\nRETURN_CODE: %u\n", return_code);

    free_ssaka_mem();
    free_schnorr_keychain(g_globals.keychain);
    free(g_globals.keychain);
    free_serversign(&server);

    //*/

    /*  PAILLIER-SHAMIR test    
    printf("\n\n---PAILLIER-SHAMIR test---\n");

    BIGNUM *sk_sum = BN_new();
    BIGNUM *sk_chck = BN_new();
    BIGNUM *order = BN_new();
    EC_POINT *pk_chck = EC_POINT_new(g_globals.keychain->ec_group);
    

    unsigned int list_of_used_devs[] = {2, 3, 1};
    unsigned int size_used = sizeof(list_of_used_devs) / sizeof(unsigned int);

    unsigned int list_of_all_devs[currentNumberOfDevices];
    for (unsigned int i = 0; i < currentNumberOfDevices; i++)
    {
        list_of_all_devs[i] = i;
    }

    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX!\n");
        goto end;
    }

    err = EC_GROUP_get_order(g_globals.keychain->ec_group, order, ctx);
    if(err != 1)
    {
        printf(" * Failed to get the EC order!\n");
        goto end;
    }

    struct paillier_Keychain p_keychain;
    init_paillier_keychain(&p_keychain);
    if (&p_keychain.pk == NULL)
    {
        printf(" * Failed to init paillier keychain!\n");
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
        g_ssaka_devicesKeys[i].pk = BN_new();
        g_ssaka_devicesKeys[i].sk = BN_new();
        g_ssaka_devicesKeys[i].kappa = BN_new();

        err = rand_range(g_ssaka_devicesKeys[i].pk, EC_GROUP_get0_order(g_globals.keychain->ec_group));
        if (err != 1)
        {
            printf(" * Generation of a random public key failed!\n");
            return_code = 0;
            goto end;
        }
    }

    err = paiShamir_distribution(&p_keychain);
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
    printf("\n"); /

    err = paiShamir_interpolation(list_of_all_devs, currentNumberOfDevices, p_keychain.sk->q, sk_chck); //order
    err = EC_POINT_mul(g_globals.keychain->ec_group, pk_chck, sk_chck, NULL, NULL, ctx);
    printf("\nRESULTS (ALL):\n|---> SK: %s\n|---> PK: %s\n",
        BN_bn2dec(sk_chck), EC_POINT_point2hex(g_globals.keychain->ec_group, pk_chck, POINT_CONVERSION_COMPRESSED, ctx));

    err = paiShamir_interpolation(list_of_used_devs, size_used, p_keychain.sk->q, sk_chck); //order
    err = EC_POINT_mul(g_globals.keychain->ec_group, pk_chck, sk_chck, NULL, NULL, ctx);
    printf("\nRESULTS (PART):\n|---> SK: %s\n|---> PK: %s\n",
        BN_bn2dec(sk_chck), EC_POINT_point2hex(g_globals.keychain->ec_group, pk_chck, POINT_CONVERSION_COMPRESSED, ctx));

end:
    printf("\nRETURN CODE: %u\n", return_code);

    BN_free(sk_chck);
    BN_free(sk_sum);
    BN_free(order);
    EC_POINT_free(pk_chck);
    free_schnorr_keychain(g_globals.keychain);
    free(g_globals.keychain);
    free_paillier_keychain(&p_keychain);

    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        BN_free(g_ssaka_devicesKeys[i].pk);
        BN_free(g_ssaka_devicesKeys[i].sk);
        BN_free(g_ssaka_devicesKeys[i].kappa);
    }

    BN_CTX_free(ctx);
    //*/

    /*  SCHNORR test    
        printf("\n\n---SCHNORR test---\n");
        int stop = 0;

        struct schnorr_Keychain s_keychain;
        struct schnorr_Signature s_signature;
        struct schnorr_Keychain c_keychain;
        struct schnorr_Signature c_signature;

        EC_POINT *s_kappa = EC_POINT_new(group);
        EC_POINT *c_kappa = EC_POINT_new(group);
        EC_POINT *zero = EC_POINT_new(group);

        BN_CTX *ctx = BN_CTX_secure_new();
        if(!ctx)
        {
            printf(" * Failed to genetare CTX!\n");
            return_code = 0;
            goto end;
        }

        err = gen_schnorr_keychain(group, &s_keychain);
        if(err != 1)
        {
            printf(" * Failed to generate EC parameters!\n");
            return_code = 0;
            goto final;
        }
        init_schnorr_signature(group, &s_signature);

        err = gen_schnorr_keychain(group, &c_keychain);
        if(err != 1)
        {
            printf(" * Failed to generate EC parameters!\n");
            return_code = 0;
            goto final;
        }
        init_schnorr_signature(group, &c_signature);

        while(stop <= 10) {
            err = 0;
            err = rand_point(group, s_kappa); // EC_POINT_new(group);
            if(err != 1)
            {
                printf(" * Failed to set S_KAPPA!\n");
                return_code = 0;
                goto end;
            }

            err = rand_point(group, c_kappa); // EC_POINT_new(group);
            if(err != 1)
            {
                printf(" * Failed to set C_KAPPA!\n");
                return_code = 0;
                goto end;
            }

            printf("\n\n~ TRY N#%d ~\n\n--- SIGNATURE SERVER ---\n", stop);
            err = schnorr_sign(&s_keychain, EC_KEY_get0_private_key(s_keychain.keys), message, zero, &s_signature);
            if(err != 1)
            {
                printf(" * EC Schnorr sign failed!\n");
                return_code = 0;
                goto end;
            }
            else
            {
                printf(" * Server signature created!\n    |--> SIG: %s\n", BN_bn2dec(s_signature.signature));
            }

            err = schnorr_verify(&s_keychain, EC_KEY_get0_public_key(s_keychain.keys), message, zero, &s_signature);
            if(err != 1)
            {
                printf(" * EC Schnorr sign failed!\n");
                return_code = 0;
                goto end;
            }
            else
            {
                printf(" * Server verification successful! :)\n");
            }

            printf("\n--- SIGNATURE CLIENT ---\n");
            EC_POINT_copy(c_signature.c_prime, s_signature.c_prime);
            err = schnorr_sign(&c_keychain, EC_KEY_get0_private_key(c_keychain.keys), message, c_kappa, &c_signature);
            if(err != 1)
            {
                printf(" * EC Schnorr sign failed!\n");
                return_code = 0;
                goto end;
            }
            else
            {
                printf(" * Server signature created!\n    |--> SIG: %s\n", BN_bn2dec(c_signature.signature));
            }

            BN_copy(c_signature.r, s_signature.r);
            err = schnorr_verify(&c_keychain, EC_KEY_get0_public_key(c_keychain.keys), message, s_kappa, &c_signature);
            if(EC_POINT_cmp(group, c_kappa, s_kappa, ctx) != 0)
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
        printf("\n\nRETURN_CODE: %u\n\n", return_code);

        EC_POINT_free(s_kappa);
        EC_POINT_free(c_kappa);

        free_schnorr_keychain(&s_keychain);
        free_schnorr_signature(&s_signature);
        free_schnorr_keychain(&c_keychain);
        free_schnorr_signature(&c_signature);
    //*/

    /*  PAILLIER test   
        printf("\n\n---PAILLIER test---\n");

        cJSON *json_noise = cJSON_CreateObject();
        cJSON *json_message = cJSON_CreateObject();

        BIGNUM *enc = BN_new();
        BIGNUM *dec = BN_new();

        BIGNUM *p_message = BN_new();
        BIGNUM *p_noise = BN_new();

        init_paillier_keychain(&g_paiKeys);
        if(&g_paiKeys == NULL)
        {
            printf(" * Failed to init PAILLIER KEYCHAIN!\n");
            return_code = 0;
            goto end;
        }

        // INIT KEYS
        if (access(file_keychain, F_OK) || access(file_precomputed_noise, F_OK) || access(file_precomputed_message, F_OK))
        {
            err = paillier_generate_keypair(&g_paiKeys);
            if(err != 1)
            {
                printf(" * Keychain generation failed!\n");
                return 0;
            }

            err = write_keys(file_keychain, &g_paiKeys);
            if(err != 0)
            {
                printf(" * Save keychain to file failed!\n");
                return 0;
            }

            threaded_precomputation();
            
            for (int i = 0; i < NUM_THREADS; i++)
            {
                pthread_join(threads[i], NULL);
            }
        }
        else
        {
            read_keys(file_keychain, &g_paiKeys);
        }

        printf("ERR: %u\nKEYS:\n|--> L: %s\n|--> MI: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n", err, BN_bn2dec(g_paiKeys.sk->lambda),
            BN_bn2dec(g_paiKeys.sk->mi), BN_bn2dec(g_paiKeys.pk->n), BN_bn2dec(g_paiKeys.pk->n_sq), BN_bn2dec(g_paiKeys.pk->g));
        printf("\n\nSECRET: %s\n", BN_bn2dec(message));

        json_noise = parse_JSON(file_precomputed_noise);
        json_message = parse_JSON(file_precomputed_message);

        
        printf("\nNO PRECOMPUTATION:\n");
        pre_message = 0;
        pre_noise = 0;
        err = set_precomps(message, p_message, p_noise);
        printf(">> PM: %s\n>> PN: %s\n", BN_bn2dec(p_message), BN_bn2dec(p_noise));
        
        err = paillier_encrypt(g_paiKeys.pk, message, enc, p_message, p_noise);
        if(err != 1)
        {
            printf(" * Failed to process the encryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        err = paillier_decrypt(&g_paiKeys, enc, dec);
        if(err != 1)
        {
            printf(" * Failed to process the decryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        printf("DEC: %s\n", BN_bn2dec(dec));


        printf("\nMESSAGE PRECOMPUTATION:\n");
        pre_message = 1;
        pre_noise = 0;
        err = set_precomps(message, p_message, p_noise);
        printf(">> PM: %s\n>> PN: %s\n", BN_bn2dec(p_message), BN_bn2dec(p_noise));

        err = paillier_encrypt(g_paiKeys.pk, message, enc, p_message, p_noise);
        if(err != 1)
        {
            printf(" * Failed to process the encryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        err = paillier_decrypt(&g_paiKeys, enc, dec);
        if(err != 1)
        {
            printf(" * Failed to process the decryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        printf("DEC: %s\n", BN_bn2dec(dec));


        printf("\nNOISE PRECOMPUTATION:\n");
        pre_message = 0;
        pre_noise = 1;
        err = set_precomps(message, p_message, p_noise);
        printf(">> PM: %s\n>> PN: %s\n", BN_bn2dec(p_message), BN_bn2dec(p_noise));

        err = paillier_encrypt(g_paiKeys.pk, message, enc, p_message, p_noise);
        if(err != 1)
        {
            printf(" * Failed to process the encryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        err = paillier_decrypt(&g_paiKeys, enc, dec);
        if(err != 1)
        {
            printf(" * Failed to process the decryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        printf("DEC: %s\n", BN_bn2dec(dec));


        printf("\nBOTH PRECOMPUTATION:\n");
        pre_message = 1;
        pre_noise = 1;
        err = set_precomps(message, p_message, p_noise); 
        printf(">> PM: %s\n>> PN: %s\n", BN_bn2dec(p_message), BN_bn2dec(p_noise));

        err = paillier_encrypt(g_paiKeys.pk, message, enc, p_message, p_noise);
        if(err != 1)
        {
            printf(" * Failed to process the encryption with Paillier!\n");
            return_code = 0;
            goto end;
        }
        err = paillier_decrypt(&g_paiKeys, enc, dec);
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

        free_paillier_keychain(&g_paiKeys);
        BN_free(enc);
        BN_free(dec);
        BN_free(p_message);
        BN_free(p_noise);
    //*/

    /*  HASH test   
        BIGNUM *res = BN_new();
        BIGNUM *one = BN_new();
        BIGNUM *zero = BN_new();
        BN_dec2bn(&one, "1");
        BN_dec2bn(&zero, "0");
        for (int i = 0; i < 20; i++) {
            err = hash(res, message, one, zero);
            if(err != 1)
            {
                printf(" * Creation of hash (%d) failed!\n", i);
                return_code = 0;
                goto end;
            }
            printf("I: %d\tHASH: %s\n", i+1, BN_bn2dec(res));
        }

    end:
        BN_free(res);
        BN_free(one);
        BN_free(zero);
    //*/

    /*  PRE-COMPUTATION test    
        BIGNUM *result = BN_new();
        g_range = BN_new();
        cJSON *json_noise = cJSON_CreateObject();
        cJSON *json_message = cJSON_CreateObject();
        unsigned char *tmp_string = (char*)malloc(sizeof(char)*BUFFER/2);

        sprintf(tmp_string, "%d", RANGE);
        BN_dec2bn(&g_range, tmp_string);

        init_paillier_keychain(&g_paiKeys);

        if (access(file_precomputed_noise, F_OK) || access(file_precomputed_message, F_OK))
        {
            if (!paillier_generate_keypair(&g_paiKeys))
            {
                printf(" * Keychain generation failed!\n");
                return 0;
            }
            threaded_precomputation();
            for (int i = 0; i < NUM_THREADS; i++)
            {
                pthread_join(threads[i], NULL);
            }
        }
        else
        {
            if(noise_precomp && access(file_precomputed_noise, F_OK))
            {
                read_keys(file_precomputed_noise, &g_paiKeys);
            }
            else if(message_precomp && access(file_precomputed_message, F_OK))
            {
                read_keys(file_precomputed_message, &g_paiKeys);
            }
        }

        json_noise = parse_JSON(file_precomputed_noise);
        err = find_value(json_noise, message, result);
        if (err != 1)
        {
            printf(" * Find value test failed!\n");
            goto end;
        }
        else
            printf("FOUND!\n|---> SECRET: %s\n|---> RESULT: %s\n", BN_bn2dec(message), BN_bn2dec(result));
        json_message = parse_JSON(file_precomputed_message);

    end:
        free_paillier_keychain(&g_paiKeys);
        BN_free(result);
        cJSON_free(json_noise);
        cJSON_free(json_message);
    //*/

final:

    EC_GROUP_free(group);
    BN_free(message);
    free(tmp_str);
    BN_free(g_range);

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