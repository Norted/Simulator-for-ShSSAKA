#include <stdio.h>
#include <stdlib.h>
#include <math.h>
// local headers
//#include <paramgen.h>
#include <SSAKA.h>
#include <AKA.h>

unsigned int test(struct aka_Keychain *server_keys, unsigned char *r_s, unsigned char *Y);

int main() {
    unsigned char *Y = "100";
    struct ServerSign server = {{""}};
    unsigned int err = 0;

    /*  AKA-SETUP and AKA-CLIENT-REGISTER   
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for devices, client and server side
     */

    /*  PARAMGEN test   */

    /* test of tests    */
        
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

    /*   SCHNORR GROUP test  
        unsigned char g[BUFFER];
        unsigned char q[BUFFER];
        err = schnorr_group(g, q);
        printf("ERR: %u\tG: %s\tQ: %s\n", err, g, q);
    */

    /*  AKA test    
        err += aka_setup();
        err += aka_serverSignVerify(Y, g_aka_clientKeys.pk, g_aka_serverKeys.sk, &server);
        printf("ERR:\t%d\nTAU:\t%s\n", err, server.tau_s);
    */

    /*  SSAKA test  
        unsigned char interpolation[BUFFER];
        err += ssaka_setup();

        unsigned char add[BUFFER];
        strcpy(add, "0");
        for (int i = 0; i < G_NUMOFDEVICES+1; i++) {
            err += bn_add(add, g_ssaka_deviceKeys[i].kappa, add);
        }

        //err += ssaka_interpolation(interpolation, 0);
        //printf("ERR: %u\nADD: %s\nINTER: %s\n", err, add, interpolation);
        
        unsigned int list_of_all_devs[G_NUMOFDEVICES];
        for (int i = 1; i < G_NUMOFDEVICES+1; i++) {
            list_of_all_devs[i-1] = (unsigned char) atoi(g_ssaka_deviceKeys[i].ID);
        }
        unsigned int size_all = sizeof(list_of_all_devs)/sizeof(unsigned int);

        struct Share share = {{""}};
        unsigned int list_of_used_devs[] = {1, 3, 4};
        unsigned int size_used = sizeof(list_of_used_devs)/sizeof(unsigned int);
        err += ssaka_ClientAddShare(&list_of_all_devs, size_all, g_ssaka_deviceKeys[0].sk, g_ssaka_deviceKeys[0].pk, &share);
        err += ssaka_akaServerSignVerify(&list_of_used_devs, size_used, Y, share.new_sk_c, g_ssaka_serverKeys.sk, &server);
        printf("ERR:\t%d\nTAU:\t%s\n", err, server.tau_s);
    */
    
    /*  My PAILLIER test    

        printf("\n\n---PAILLIER test---\n");
        struct paillierKeychain p_keyring = {{""}};
        unsigned int err = generate_keypair(&p_keyring);

        printf("ERR: %u\nKEYS:\n|--> L: %s\n|--> M: %s\n|--> N: %s\n|--> N_SQ: %s\n|--> G: %s\n", err, p_keyring.sk.l,
            p_keyring.sk.m, p_keyring.pk.n, p_keyring.pk.n_sq, p_keyring.pk.g);
        
        unsigned char *secret = "125";
        printf("SECRET: %s\n", secret);
        unsigned char enc[BUFFER];
        encrypt(p_keyring.pk, secret, enc);
        printf("ENC: %s\n", enc);
        unsigned char dec[BUFFER];
        decrypt(&p_keyring, enc, dec);
        printf("DEC: %s\n", dec);
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

    return 0;
}

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

/*
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
*/
    
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

/* --- RESOURCES ---
 *  https://math.stackexchange.com/questions/814879/find-a-generator-of-the-multiplicative-group-of-mathbbz-23-mathbbz-as-a-c
 *  https://stackoverflow.com/questions/23360728/how-to-generate-a-number-of-n-bit-in-length
 *  https://stackoverflow.com/questions/2844/how-do-you-format-an-unsigned-long-long-int-using-printf
 *  
 *  ~~~ WOLFSSL ~~~
 *  https://www.wolfssl.com/
 */