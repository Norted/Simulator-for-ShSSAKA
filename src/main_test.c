#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
// local headers
//#include <paramgen.h>
#include <schnorrs_signature.h>
#include <paillier.h>
#include <paishamir.h>
#include <SSAKA.h>
#include <AKA.h>


struct globals g_globals;
unsigned int test(struct aka_Keychain *server_keys, unsigned char *r_s, unsigned char *Y);
unsigned int test_2(unsigned char *Y);

int main() {
    unsigned char *Y = "100";
    struct ServerSign server = {{""}};
    unsigned int err = 0;

    //err = test_2(Y);
    
    /*  AKA-SETUP and AKA-CLIENT-REGISTER   
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for devices, client and server side
     */

    /*  AKA test    
        g_globals.params = malloc(sizeof(struct SchnorrParams));
        gen_schnorr_params(g_globals.params);
        g_globals.idCounter = 1;

        err += aka_setup();
        err += aka_serverSignVerify(Y, &server);
        printf("ERR:\t%d\nTAU:\t%s\n", err, server.tau_s);
    */

    /*  SSAKA test  
        g_globals.params = malloc(sizeof(struct SchnorrParams));
        gen_schnorr_params(g_globals.params);
        g_globals.idCounter = 1;
        
        err += ssaka_setup();
        
        unsigned int list_of_all_devs[currentNumberOfDevices-1];
        for (int i = 1; i < currentNumberOfDevices; i++) {
            list_of_all_devs[i-1] = i;  //(unsigned int) atoi(g_ssaka_devicesKeys[i].ID);
        }
        unsigned int size_all = sizeof(list_of_all_devs)/sizeof(unsigned int);

        unsigned int list_of_used_devs[] = {1, 2};
        unsigned int size_used = sizeof(list_of_used_devs)/sizeof(unsigned int);
        
        /*
            err += ssaka_ClientAddShare(3);
            printf("\n+++ ADDED! +++\n");
            for (int j = 1; j < currentNumberOfDevices; j++) {
                printf("--- DEVICE %d ---\n", j);
                _ssaka_keyPrinter(&g_ssaka_devicesKeys[j]);
            }

            unsigned int remove[] = {1, 3};
            unsigned int size_remove = sizeof(remove)/sizeof(unsigned int);
            err += ssaka_ClientRevShare(remove, size_remove);

            printf("\n--- REMOVED ---\n");
            for (int j = 1; j < currentNumberOfDevices; j++) {
                printf("--- DEVICE %d ---\n", j);
                _ssaka_keyPrinter(&g_ssaka_devicesKeys[j]);
            }
        /

        err += ssaka_akaServerSignVerify(&list_of_used_devs, size_used, Y, &server);
        //err += ssaka_akaServerSignVerify(&list_of_all_devs, size_all, Y, &server); 
        printf("ERR:\t%d\nTAU:\t%s\n", err, server.tau_s);
    */
    
    /*  Paillier-Shamir test    
        struct paillierKeychain paikeys;
        err += generate_keypair(&paikeys);
        
        g_globals.params = malloc(sizeof(struct SchnorrParams));
        gen_schnorr_params(g_globals.params);
        g_globals.idCounter = 1;

        for (int i = 0; i < currentNumberOfDevices; i++) {
            g_ssaka_devicesKeys[i].keys = malloc(sizeof(struct SchnorrKeychain));
            err += random_str_num_in_range(g_ssaka_devicesKeys[i].keys->pk, atoi(paikeys.pk.n)-1, 1);
        }

        unsigned int list_of_all_devs[currentNumberOfDevices];
        for (int i = 0; i < currentNumberOfDevices; i++) {
            list_of_all_devs[i] = i;  //(unsigned int) atoi(g_ssaka_devicesKeys[i].ID);
        }
        unsigned int size_all = sizeof(list_of_all_devs)/sizeof(unsigned int);

        //unsigned char *secret = "1234";
        //err += shamir_distribution(secret);
        err += paiShamir_distribution(&paikeys);

        printf("\n---DEVICES---\n");
        for (int i = 0; i < currentNumberOfDevices; i++) {
            printf("\n- DEVICE %d -\n", i);
            _ssaka_keyPrinter(&g_ssaka_devicesKeys[i]);
        }
        printf("\n");

        unsigned char secret_chck[BUFFER];
        unsigned int list_of_used_devs[] = {1, 3, 2};
        unsigned int size_used = sizeof(list_of_used_devs)/sizeof(unsigned int);
        err += paiShamir_interpolation(list_of_used_devs, size_used, secret_chck);
        //err += paiShamir_interpolation(list_of_all_devs, size_all, secret_chck);
       
        printf("\nCHCK: %s\n", secret_chck);
        printf("\nMAIN-ERR: %d\n", err);
    */

    /*   SCHNORR test  
        int stop = 0;
        struct SchnorrParams params = {{""}};
        struct SchnorrKeychain keys_s = {{""}};
        struct SchnorrSignature sign_s = {{""}};
        struct SchnorrKeychain keys_c = {{""}};
        struct SchnorrSignature sign_c = {{""}};

        unsigned char kappa_s[BUFFER];
        strcpy(kappa_s, "1");
        unsigned char kappa_c[BUFFER];
        strcpy(kappa_c, "1");
        
        
        err += gen_schnorr_params(&params);
        printf("--- PARAMETERS ---\nERR: %u\nG: %s\tP: %s\tQ: %s\n", err, params.g, params.p, params.q);
        err += gen_schnorr_keys(&keys_s);
        printf("\n--- KEYS SERVER --- \nERR: %u\nPK: %s\nSK: %s\n", err, keys_s.pk, keys_s.sk);
        err += gen_schnorr_keys(&keys_c);
        printf("\n--- KEYS CLIENT--- \nERR: %u\nPK: %s\nSK: %s\n", err, keys_c.pk, keys_c.sk);

        unsigned char hash_prime[BUFFER];

        while(stop <= 20) {
            err = 0;
            strcpy(kappa_s, "1");
            strcpy(kappa_c, "1");

            printf("TRY N#%d\n", stop);
            err += schnorr_sign(&params, &keys_s.sk, Y, "0", &sign_s);
            strcpy(hash_prime, sign_s.hash);
            printf("\n--- SIGNATURE SERVER ---\nERR: %u\nSIGNATURE: %s\nHASH: %s\n", err, sign_s.signature, sign_s.hash);
            err += schnorr_verify(&params, &keys_s.pk, Y, "0", &sign_s);
            
            if(err == 2)
                printf("\nVERIFICATION PROCEEDED! :)\t(ERR: %u)\n", err);
            else {
                printf("\nVERIFICATION FAILED! :(\t(ERR: %u)\n", err);
            }
            
            strcpy(sign_c.c_prime, sign_s.c_prime);
            err += schnorr_sign(&params, &keys_c.sk, Y, kappa_c, &sign_c);
            printf("\n--- SIGNATURE CLIENT ---\nERR: %u\nSIGNATURE: %s\nHASH: %s\nKAPPA_C: %s\n", err, sign_c.signature, sign_c.hash, kappa_c);

            strcpy(sign_c.r, sign_s.r);
            err += schnorr_verify(&params, &keys_c.pk, Y, kappa_s, &sign_c);


            if(strcmp(kappa_c, kappa_s) == 0) {
                printf("\nVERIFICATION PROCEEDED! :)\t(ERR: %u)\nKAPPA_S: %s\n", err, kappa_s);
                break;
            }
            else {
                printf("\nVERIFICATION FAILED! :(\t(ERR: %u)\nKAPPA_S: %s\n", err, kappa_s);
            }
            stop ++;
        }
    */

    /*  My PAILLIER test    
        printf("\n\n---PAILLIER test---\n");
        struct paillierKeychain p_keyring = {{""}};
        err += generate_keypair(&p_keyring);

        printf("ERR: %u\nKEYS:\n|--> L: %s\n|--> M: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n", err, p_keyring.sk.l,
            p_keyring.sk.m, p_keyring.pk.n, p_keyring.pk.n_sq, p_keyring.pk.g);
        
        unsigned char *secret = "125";
        printf("SECRET: %s\n", secret);
        unsigned char enc[BUFFER];
        err += encrypt(p_keyring.pk, secret, enc);
        printf("ENC: %s\n", enc);
        unsigned char dec[BUFFER];
        err += decrypt(&p_keyring, enc, dec);
        printf("DEC: %s\n", dec);

        printf("\n---HOMOMORPHIC TEST---\n");
        err += test_homomorphic();

        printf("\n\nERR: %u (?= 4)\n", err);
    */

    /*  test of HASH    
        unsigned char res[BUFFER];
        unsigned char t_s[BUFFER];
        for (int i = 1; i <= 20; i++) {
            err += hash(res, Y, "1", "0");
            sprintf(t_s, "%d", i);
            printf("I: %d\tHASH: %s\n", i, res);
        }
    */
    
    /*  test BN_LIB 
        unsigned char *a = "21";
        unsigned char *b = "42";
        unsigned char *mod = "9";
        unsigned char *base = "17891";
        unsigned char *exp = "12345678901234567890";

        unsigned char res[BUFFER];
        unsigned char rem[BUFFER];

        err = bn_add(a, b, res);
        printf("ADD: %s, %u\n", res, err);
        err = bn_sub(a, b, res);
        printf("SUB: %s, %u\n", res, err);
        err = bn_mul(a, b, res);
        printf("MUL: %s, %u\n", res, err);
        err = bn_div(a, b, res, rem);
        printf("DIV: %s, %s, %u\n", res, rem, err);
        err = bn_exp(base, exp, res);
        printf("EXP: %s, %u\n", res, err);
        err = bn_mod(a, mod, res);
        printf("MOD: %s, %u\n", res, err);
        err = bn_modadd(a, b, mod, res);
        printf("MODADD: %s, %u\n", res, err);
        err = bn_modmul(a, b, mod, res);
        printf("MODMUL: %s, %u\n", res, err);
        err = bn_modexp(base, exp, mod, res);
        printf("MODEXP: %s, %u\n", res, err);
        err = bn_gcd(a, b, res);
        printf("GCD: %s, %u\n", res, err);
    */

    //free_aka_mem();
    //free_ssaka_mem();
    //free_schnorr_mem();

    /*  ultimately desperate test of tests v1    
        
        unsigned char g[BUFFER];
        unsigned char p[BUFFER];
        unsigned char q[BUFFER];
        //for(int z = 0; z < 10; z++) {
            err += bn_genparams(p, q, g);

            strcpy(g_globals.g_q, q);
            strcpy(g_globals.g_g, g);
            g_globals.g_idCounter = 1;

            printf("--- PARAMS ---\n");
            printf("Q: %s\n", g_globals.g_q);
            printf("G: %s\n", g_globals.g_g);

            for(int j = 1; j <= 19; j++) {
                struct aka_Keychain server_keys = {{""}};
                int u = sprintf(server_keys.sk, "%d", j);
            
                err += bn_exp(g_globals.g_g, server_keys.sk, server_keys.pk);
                sprintf(server_keys.ID, "%u", g_globals.g_idCounter++);
                printf("SK: %s\n", server_keys.sk);

                unsigned char r_s[BUFFER];
                for(int i = 1; i <= 19; i++) {
                    //printf("---TRY %d--------------------\n", i);
                    int u = sprintf(r_s, "%d", i);
                    err = test(&server_keys, &r_s, Y);
                }
                printf("\n--------------------------------------------\n");
            }

            printf("============================================\n");
            printf("============================================\n");
            printf("============================================\n");
        //}
    */

    return 0;
}

/*
    unsigned int test(struct aka_Keychain *server_keys, unsigned char *r_s, unsigned char *Y) {
        unsigned int err = 0;
        unsigned char t_s[BUFFER];
        unsigned char e_s[BUFFER];
        unsigned char s_s[BUFFER];
        unsigned char mul[BUFFER];
        unsigned char sub[BUFFER];
        unsigned char t_s_chck_1[BUFFER];
        unsigned char t_s_chck_2[BUFFER];
        unsigned char t_s_chck[BUFFER];
        unsigned char *zero = "0";
        int set = 0;


        t_s[0] = '\0';
        e_s[0] = '\0';
        s_s[0] = '\0';
        mul[0] = '\0';
        sub[0] = '\0';
        t_s_chck_1[0] = '\0';
        t_s_chck_2[0] = '\0';
        t_s_chck[0] = '\0';

        for (int i = 1; i < BUFFER; i++) {
            t_s[i] = '0';
            e_s[i] = '0';
            s_s[i] = '0';
            mul[i] = '0';
            sub[i] = '0';
            t_s_chck_1[i] = '0';
            t_s_chck_2[i] = '0';
            t_s_chck[i] = '0';
        }

        
        err += bn_modexp(g_globals.g_g, r_s, g_globals.g_q, t_s);  //t_s 
        err += hash(e_s, Y, t_s, zero);
        err += bn_mul(e_s, server_keys->sk, mul);
        err += bn_sub(r_s, mul, sub);
        err += bn_mod(sub, g_globals.g_q, s_s);
        
        
        err += bn_modexp(g_globals.g_g, s_s, g_globals.g_q, t_s_chck_1);
        err += bn_modexp(server_keys->pk, e_s, g_globals.g_q, t_s_chck_2);
        err += bn_modmul(t_s_chck_1, t_s_chck_2, g_globals.g_q, t_s_chck);
        
        unsigned char test[BUFFER];
        unsigned char *one = "1";
        err += bn_sub(t_s_chck, one, test);

        if(bn_cmp(t_s, test) == 0) {
            printf("%s! ", r_s);
            set = 1;
        }

        if(bn_cmp(t_s, t_s_chck) == 0) {
            printf("%s* ", r_s);
            set = 1;
        }

        //printf("T_S: %s\t\tT_S_CHCK: %s\n", t_s, t_s_chck);
        
        return set;
    }
*/

/*
unsigned int test_2(unsigned char *Y) {
    struct SchnorrParams params = {{""}};
    struct SchnorrKeychain keys_server = {{""}};
    struct SchnorrKeychain keys_client = {{""}};
    struct SchnorrKeychain keys_device1 = {{""}};
    struct SchnorrKeychain keys_device2 = {{""}};
    unsigned int err = 0;

    err += gen_schnorr_params(&params);
    err += gen_schnorr_keys(&keys_server);
    err += gen_schnorr_keys(&keys_client);
    err += gen_schnorr_keys(&keys_device1);
    err += gen_schnorr_keys(&keys_device2);

    struct paillierKeychain paikeys = {{""}};
    err += generate_keypair(&paikeys);

    unsigned char SUM[BUFFER];
    strcpy(SUM, "0");

    unsigned char c[BUFFER];
    unsigned char ci[BUFFER];
    unsigned char cN_prime[BUFFER];
    unsigned char kappa_inter[3][BUFFER];
    unsigned char d[3][G_POLYDEGREE][BUFFER];
    for (int i = 0; i < 3; i++) {
        err += random_str_num_in_range(kappa_inter[i], atoi(paikeys.pk.n)-1, 1);
        err += bn_add(SUM, kappa_inter[i], SUM);
        for(int j = 0; j < G_POLYDEGREE; j++) {
            err += random_str_num_in_range(d[i][j], atoi(paikeys.pk.n)-1, 1);
        }
    }
    //printf("\n");
    
    // SHARE
    err += paiShamir_get_ci(&paikeys, kappa_inter[0], d[0], keys_client.pk, c);
    err += paiShamir_get_ci(&paikeys, kappa_inter[1], d[1], keys_client.pk, cN_prime);
    err += paiShamir_get_ci(&paikeys, kappa_inter[2], d[2], keys_client.pk, ci);
    err += paiShamir_get_cN_prime(&paikeys, cN_prime, ci, cN_prime);
    err += paiShamir_get_share(&paikeys, cN_prime, c, keys_client.sk);

    err += paiShamir_get_ci(&paikeys, kappa_inter[1], d[1], keys_device1.pk, c);
    err += paiShamir_get_ci(&paikeys, kappa_inter[2], d[2], keys_device1.pk, cN_prime);
    err += paiShamir_get_ci(&paikeys, kappa_inter[0], d[0], keys_device1.pk, ci);
    err += paiShamir_get_cN_prime(&paikeys, cN_prime, ci, cN_prime);
    err += paiShamir_get_share(&paikeys, cN_prime, c, keys_device1.sk);

    err += paiShamir_get_ci(&paikeys, kappa_inter[2], d[2], keys_device2.pk, c);
    err += paiShamir_get_ci(&paikeys, kappa_inter[0], d[0], keys_device2.pk, cN_prime);
    err += paiShamir_get_ci(&paikeys, kappa_inter[1], d[1], keys_device2.pk, ci);
    err += paiShamir_get_cN_prime(&paikeys, cN_prime, ci, cN_prime);
    err += paiShamir_get_share(&paikeys, cN_prime, c, keys_device2.sk);
    //printf("SK_%d: %s\n", i, g_ssaka_devicesKeys[i].keys->sk);

    printf("\nKappa_SUM: %s\n\n", SUM);
    err += bn_modexp(params.g,SUM,params.p,SUM);
    printf("\nKappa_PK: %s\n\n", SUM);


    unsigned char sk_sum[BUFFER];
    strcpy(sk_sum, kappa_inter[0]);
    err += bn_add(sk_sum, kappa_inter[1], sk_sum);
    err += bn_add(sk_sum, kappa_inter[2], sk_sum);
    printf("SK_C: %s\nSK_D1: %s\nSK_D2: %s\nSK_SUM: %s\n\n", kappa_inter[0], kappa_inter[1], kappa_inter[2], sk_sum);

    unsigned char pk[BUFFER];
    strcpy(pk, keys_client.pk);
    err += bn_mul(pk, keys_device1.pk, pk);
    err += bn_mul(pk, keys_device2.pk, pk);
    unsigned char pk_ch[BUFFER];
    err += bn_modexp(params.g, sk_sum, params.p, pk_ch);
    printf("PK: %s\nPK_CH: %s\n\n\n", pk, pk_ch);
    
    unsigned char r_s[BUFFER];
    err += random_str_num_in_range(r_s, atoi(params.q)-1, 1);
    unsigned char t_s[BUFFER];
    err += bn_modexp(params.g, r_s, params.p, t_s);
    unsigned char e_s[BUFFER];
    err += hash(e_s, Y, t_s, "0");
    unsigned char s_s[BUFFER];
    unsigned char s_s_mul[BUFFER];
    err += bn_modmul(e_s, keys_server.sk, params.q, s_s_mul);
    err += bn_modsub(r_s, s_s_mul, params.q, s_s);

    //--------------------------

    unsigned char t_s_ch[BUFFER];
    unsigned char ch_1[BUFFER];
    unsigned char ch_2[BUFFER];
    err += bn_modexp(params.g, s_s, params.p, ch_1);
    err += bn_modexp(keys_server.pk, e_s, params.p, ch_2);
    err += bn_modmul(ch_1, ch_2, params.p, t_s_ch);
    unsigned char e_s_ch[BUFFER];
    err += hash(e_s_ch, Y, t_s_ch, "0");

    int tau_c = bn_cmp(e_s, e_s_ch);
    printf("TAU_C: %d\n", tau_c);

    unsigned char r_c[BUFFER];
    err += random_str_num_in_range(r_c, atoi(params.q)-1, 1);
    
    unsigned char r_i[2][BUFFER];
    unsigned char t_i[2][BUFFER];
    unsigned char kappa_i[2][BUFFER];
    for(int i = 0; i < 2; i++) {
        err += random_str_num_in_range(r_i[i], atoi(params.q)-1, 1);
        err += bn_modexp(params.g, r_i[i], params.p, t_i[i]);
        err += bn_modexp(t_s_ch, r_i[i], params.p, kappa_i[i]);
    }
    
    unsigned char t_c[BUFFER];
    err += bn_modexp(params.g, r_c, params.p, t_c);
    unsigned char kappa_c[BUFFER];
    err += bn_modexp(t_s_ch, r_c, params.p, kappa_c);
    for(int i = 0; i < 2; i++) {
        err += bn_modmul(t_c, t_i[i], params.p, t_c);
        err += bn_modmul(kappa_c, kappa_i[i], params.p, kappa_c);
    }

    unsigned char e_c[BUFFER];
    err += hash(e_c, Y, t_c, kappa_c);

    unsigned char s_i[2][BUFFER];
    unsigned char sub[BUFFER];
    unsigned char inv[BUFFER];
    unsigned char mul[BUFFER];
    strcpy(s_i[0], keys_device1.sk);
    err += bn_modsub(keys_device2.pk, keys_device1.pk, params.q, sub);
    err += bn_modinverse(sub, params.q, inv);
    err += bn_modmul(keys_device2.pk, inv, params.q, mul);
    err += bn_modmul(s_i[0], mul, params.q, s_i[0]);

    err += bn_modsub(keys_client.pk, keys_device1.pk, params.q, sub);
    err += bn_modinverse(sub, params.q, inv);
    err += bn_modmul(keys_client.pk, inv, params.q, mul);
    err += bn_modmul(s_i[0], mul, params.q, s_i[0]);

    strcpy(s_i[1], keys_device2.sk);
    err += bn_modsub(keys_device1.pk, keys_device2.pk, params.q, sub);
    err += bn_modinverse(sub, params.q, inv);
    err += bn_modmul(keys_device1.pk, inv, params.q, mul);
    err += bn_modmul(s_i[1], mul, params.q, s_i[1]);

    err += bn_modsub(keys_client.pk, keys_device2.pk, params.q, sub);
    err += bn_modinverse(sub, params.q, inv);
    err += bn_modmul(keys_client.pk, inv, params.q, mul);
    err += bn_modmul(s_i[1], mul, params.q, s_i[1]);

    unsigned char si_sum[BUFFER];
    strcpy(si_sum, s_i[0]);
    err += bn_modadd(si_sum, s_i[1], params.q, si_sum);

    err += bn_modmul(e_c, s_i[0], params.q, s_i[0]);
    err += bn_modmul(e_c, s_i[1], params.q, s_i[1]);
    err += bn_modsub(r_i[0], s_i[0], params.q, s_i[0]);
    err += bn_modsub(r_i[1], s_i[1], params.q, s_i[1]);

    unsigned char sc_inter[BUFFER];
    strcpy(sc_inter, keys_client.sk);
    err += bn_modsub(keys_device1.pk, keys_client.pk, params.q, sub);
    err += bn_modinverse(sub, params.q, inv);
    err += bn_modmul(keys_device1.pk, inv, params.q, mul);
    err += bn_modmul(sc_inter, mul, params.q, sc_inter);

    err += bn_modsub(keys_device2.pk, keys_client.pk, params.q, sub);
    err += bn_modinverse(sub, params.q, inv);
    err += bn_modmul(keys_device2.pk, inv, params.q, mul);
    err += bn_modmul(sc_inter, mul, params.q, sc_inter);

    err += bn_modadd(si_sum, sc_inter, params.q, si_sum);
    printf("SI_SUM: %s\n", si_sum);

    unsigned char s_c[BUFFER];
    unsigned char s_c_mul[BUFFER];
    err += bn_modmul(e_c, sc_inter, params.q, s_c_mul);
    err += bn_modsub(r_c, s_c_mul, params.q, s_c);
    err += bn_modadd(s_c, s_i[0], params.q, s_c);
    err += bn_modadd(s_c, s_i[1], params.q, s_c);

    //--------------------------

    unsigned char t_ch[BUFFER];
    unsigned char tch_1[BUFFER];
    unsigned char tch_2[BUFFER];
    err += bn_modexp(params.g, s_c, params.p, tch_1);
    err += bn_modexp(pk, e_c, params.p, tch_2);
    err += bn_modmul(tch_1, tch_2, params.p, t_ch);
    unsigned char kappa_s[BUFFER];
    err += bn_modexp(t_ch, r_s, params.p, kappa_s);
    unsigned char e_c_ch[BUFFER];
    err += hash(e_c_ch, Y, t_ch, kappa_s);

    int tau_s = bn_cmp(e_c, e_c_ch);
    printf("TAU_S: %d\n", tau_s);

    return err;
}
*/

/* --- RESOURCES ---
 *  https://math.stackexchange.com/questions/814879/find-a-generator-of-the-multiplicative-group-of-mathbbz-23-mathbbz-as-a-c
 *  https://stackoverflow.com/questions/23360728/how-to-generate-a-number-of-n-bit-in-length
 *  https://stackoverflow.com/questions/2844/how-do-you-format-an-unsigned-long-long-int-using-printf
 *  
 *  ~~~ WOLFSSL ~~~
 *  https://www.wolfssl.com/
 */