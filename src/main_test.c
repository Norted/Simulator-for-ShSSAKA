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
BIGNUM *pk_c;

// Other globals
struct globals g_globals;
unsigned int currentNumberOfDevices = 4;
DSA *dsa;
BIGNUM *range;
unsigned int pre_noise = 0;
unsigned int pre_message = 0;

// File names
const char *restrict file_precomputed_noise = "../precomputed_values/precomputation_noise.json";
const char *restrict file_precomputed_message = "../precomputed_values/precomputation_message.json";

unsigned int test_homomorphy();
unsigned int test_paiShamir();

int main(void)
{
    unsigned int return_code = 1;
    unsigned int err = 0;

    dsa = DSA_new();
    if(!dsa)
    {
        printf(" * DSA initialization failed!\n");
        return 0;
    }

    g_globals.idCounter = 1;
    g_globals.params = (struct schnorr_Params *)malloc(sizeof(struct schnorr_Params));
    if (g_globals.params == NULL)
    {
        printf(" * PARAMS ALOCATION FAILED!\n");
        return_code = 0;
        return 0;
    }
    init_schnorr_params(g_globals.params);
    err = gen_schnorr_params(dsa, g_globals.params);
    if (err != 1)
    {
        printf(" * Failed to generate Schnorr params!\n");
        return_code = 0;
        return 0;
    }

    BIGNUM *pk_c = BN_new();
    BIGNUM * message = BN_new();
    BN_dec2bn(&message, "123");
    

    /*  AKA-SETUP and AKA-CLIENT-REGISTER
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for devices, client and server side
     */

    /*  AKA test    

        struct ServerSign server;
        init_serversign(&server);

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
    //*/

    /*  SSAKA test  
        printf("\n\n---SSAKA test---\n");

        unsigned int list_of_all_devs[currentNumberOfDevices-1];
        for (int i = 1; i < currentNumberOfDevices; i++) {
            list_of_all_devs[i-1] = i;
        }
        unsigned int size_all = sizeof(list_of_all_devs)/sizeof(unsigned int);

        unsigned int list_of_used_devs[] = {1, 2};
        unsigned int size_used = sizeof(list_of_used_devs)/sizeof(unsigned int);

        struct ServerSign server;
        init_serversign(&server);

        err = ssaka_setup();
        if(err != 1)
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

        /*err = ssaka_akaServerSignVerify(list_of_all_devs, size_all, message, &server);
        if(err != 1)
        {
            printf(" * SSAKA Server Sign Verify failed!\n");
            return_code = 0;
            goto end;
        }

        printf("ERR:\t%d\nTAU:\t%s\n", err, BN_bn2dec(server.tau_s));/


        err = ssaka_akaServerSignVerify(list_of_used_devs, size_used, message, &server);
        if(err != 1)
        {
            printf(" * SSAKA Server Sign Verify failed!\n");
            return_code = 0;
            goto end;
        } 
        
        printf("ERR:\t%d\nTAU:\t%s\n", err, BN_bn2dec(server.tau_s));
       
    
    end:
        printf("\n\nRETURN_CODE: %u\n", return_code);

        free_ssaka_mem();
        free_schnorr_params(g_globals.params);
        free(g_globals.params);
        free_serversign(&server);

    //*/

    /*  PAILLIER-SHAMIR test   
    printf("\n\n---PAILLIER-SHAMIR test---\n");

    BIGNUM *sk_sum = BN_new();
    BIGNUM *sk_chck = BN_new();
    BIGNUM *pk_chck = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    

    unsigned int list_of_used_devs[] = {2, 3, 1};
    unsigned int size_used = sizeof(list_of_used_devs) / sizeof(unsigned int);

    unsigned int list_of_all_devs[currentNumberOfDevices];
    for (unsigned int i = 0; i < currentNumberOfDevices; i++)
    {
        list_of_all_devs[i] = i;
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
        g_ssaka_devicesKeys[i].keys = (struct schnorr_Keychain *)malloc(sizeof(struct schnorr_Keychain));
        init_schnorr_keychain(g_ssaka_devicesKeys[i].keys);
        g_ssaka_devicesKeys[i].kappa = BN_new();

        err = rand_range(g_ssaka_devicesKeys[i].keys->pk, g_globals.params->q);
        //err = ssaka_KeyGeneration(&g_ssaka_devicesKeys[i]);
        if (err != 1)
        {
            printf(" * Generation of a random public key failed!\n");
            return_code = 0;
            goto end;
        }
    }

    // err = _shamir_distribution(message);
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

    err = paiShamir_interpolation(list_of_all_devs, currentNumberOfDevices, sk_chck);
    err = BN_mod_exp(pk_chck, g_globals.params->g, sk_chck, g_globals.params->q, ctx);
    printf("\nRESULTS (ALL):\n|---> SK: %s\n|---> PK: %s\n",
    BN_bn2dec(sk_chck), BN_bn2dec(pk_chck));

    err = paiShamir_interpolation(list_of_used_devs, size_used, sk_chck);
    err = BN_mod_exp(pk_chck, g_globals.params->g, sk_chck, g_globals.params->q, ctx);
    printf("\nRESULTS (PART):\n|---> SK: %s\n|---> PK: %s\n",
    BN_bn2dec(sk_chck), BN_bn2dec(pk_chck));

end:
    printf("\nRETURN CODE: %u\n", return_code);

    BN_free(sk_chck);
    BN_free(sk_sum);
    BN_free(pk_chck);
    free_schnorr_params(g_globals.params);
    free(g_globals.params);
    free_paillier_keychain(&p_keychain);

    for (int i = 0; i < currentNumberOfDevices; i++)
    {
        free_schnorr_keychain(g_ssaka_devicesKeys[i].keys);
        free(g_ssaka_devicesKeys[i].keys);
    }

    BN_CTX_free(ctx);
    //*/

    /*  SCHNORR test    
        printf("\n\n---SCHNORR test---\n");
        int stop = 0;

        // struct schnorr_Params params;
        // init_schnorr_params(&params);
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

        BIGNUM *zero = BN_new();
        BN_dec2bn(&zero, "0");


        /* err = gen_schnorr_params(dsa, &params);
        if(err != 1)
        {
            printf(" * Failed to generate Schnorr parameters!\n");
            return_code = 0;
            goto end;
        }
        printf("--- PARAMETERS ---\nG: %s\nQ: %s\n", BN_bn2dec(params.g), BN_bn2dec(params.q)); /
        

        err = gen_schnorr_keys(dsa, &keys_s);
        if(err != 1)
        {
            printf(" * Failed to generate server's Schnorr keychain!\n");
            return_code = 0;
            goto end;
        }
        printf("\n--- KEYS SERVER --- \nPK: %s\nSK: %s\n", BN_bn2dec(keys_s.pk), BN_bn2dec(keys_s.sk));
        

        err = gen_schnorr_keys(dsa, &keys_c);
        if(err != 1)
        {
            printf(" * Failed to generate client's Schnorr keychain!\n");
            return_code = 0;
            goto end;
        }
        printf("\n--- KEYS CLIENT--- \nPK: %s\nSK: %s\n", BN_bn2dec(keys_c.pk), BN_bn2dec(keys_c.sk));



        while(stop <= 10) {
            err = 0;
            BN_dec2bn(&kappa_s, "1");
            BN_dec2bn(&kappa_c, "1");

            printf("\n\n~ TRY N#%d ~\n\n--- SIGNATURE SERVER ---\n", stop);
            err = schnorr_sign(g_globals.params, keys_s.sk, message, zero, &sign_s); // &params
            if(err != 1)
            {
                printf(" * Schnorr server signin failed!\n");
                return_code = 0;
                goto end;
            }
            
            printf("SIGNATURE: %s\nHASH: %s\n", BN_bn2dec(sign_s.signature), BN_bn2dec(sign_s.hash));
            err = schnorr_verify(g_globals.params, keys_s.pk, message, zero, &sign_s); // &params
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


            printf("\n--- SIGNATURE CLIENT ---\n");
            BN_copy(sign_c.c_prime, sign_s.c_prime);
            err = schnorr_sign(g_globals.params, keys_c.sk, message, kappa_c, &sign_c); // &params
            if(err != 1)
            {
                printf(" * Schnorr client signin failed!\n");
                return_code = 0;
                goto end;
            }
            printf("SIGNATURE: %s\nHASH: %s\n\nKAPPA_C: %s\n", BN_bn2dec(sign_c.signature), BN_bn2dec(sign_c.hash), BN_bn2dec(kappa_c));

            BN_copy(sign_c.r, sign_s.r);
            err = schnorr_verify(g_globals.params, keys_c.pk, message, kappa_s, &sign_c); // &params
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
        printf("\n\nRETURN_CODE: %u\n\n", return_code);

        //free_schnorr_params(&params);
        free_schnorr_keychain(&keys_c);
        free_schnorr_keychain(&keys_s);
        free_schnorr_signature(&sign_c);
        free_schnorr_signature(&sign_s);
        BN_free(kappa_c);
        BN_free(kappa_s);
        BN_free(zero);
    //*/

    /*  PAILLIER test   
        printf("\n\n---PAILLIER test---\n");

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

    /*  PRE_COMPUTATION test    
        BIGNUM *result = BN_new();
        range = BN_new();
        cJSON *json_noise = cJSON_CreateObject();
        cJSON *json_message = cJSON_CreateObject();
        unsigned char *tmp_string = (char*)malloc(sizeof(char)*BUFFER/2);

        sprintf(tmp_string, "%d", RANGE);
        BN_dec2bn(&range, tmp_string);

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
        BN_free(result);
        cJSON_free(json_noise);
        cJSON_free(json_message);
    //*/

    free_paillier_keychain(&g_paiKeys);
    BN_free(message);
    BN_free(pk_c);
    DSA_free(dsa);

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