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

unsigned int aka_setup() {
    unsigned int err = 0;
    int i = 0;
    
    printf("---SERVER---\n");
    err += aka_initKeys(&g_aka_serverKeys);

    printf("\n---CLIENT---\n");
    err += aka_initKeys(&g_aka_clientKeys);

    printf("\n");

    if(err != 2)
        return 0;

    return 1;
}

// initialize the keychain with computed values
unsigned int aka_initKeys(struct aka_Keychain *keys) {
    keys->keys = malloc(sizeof(struct SchnorrKeychain));
    unsigned int err = gen_schnorr_keys(keys->keys);
    sprintf(keys->ID, "%u", g_globals.idCounter++);
    
    _aka_keyPrinter(keys);

    return err;
}

unsigned int aka_serverSignVerify (unsigned char * Y, struct ServerSign *server) {
    unsigned int err = 0;
    struct ClientProof client ={{""}};
    client.signature = malloc(sizeof(struct SchnorrSignature));
    struct SchnorrSignature signature = {{""}};

    if (strncmp(Y, "0", sizeof(Y)) == 0 || strncmp(g_aka_serverKeys.keys->sk, "0", sizeof(g_aka_serverKeys.keys->sk)) == 0 || strncmp(g_aka_clientKeys.keys->pk, "0", sizeof(g_aka_clientKeys.keys->pk)) == 0) {
        strcpy(server->tau_s, "0");
        printf("Y, SERVER sk or CLIENT pk == 0!\n");
        return 0;
    }

    err += schnorr_sign(g_globals.params, g_aka_serverKeys.keys->sk, Y, "0", &signature);
    /*
        unsigned char r_s[BUFFER];
        unsigned char t_s[BUFFER];

        unsigned char *rnd = malloc(sizeof(unsigned int));
        err += random_str_num_in_range(rnd, G_MAXRANDOMNUMBER, G_MINRANDOMNUMBER);
        err += bn_mod(rnd, g_globals.g_q, r_s);
        err += bn_modexp(g_globals.g_g, r_s, g_globals.g_q, t_s);  //t_s 

        free(rnd);

        unsigned char e_s[BUFFER];
        unsigned char s_s[BUFFER];
        err += hash(e_s, Y, t_s, "0");
        
        unsigned char mul[BUFFER];
        err += bn_modmul(e_s, sk_s, g_globals.g_q, mul);
        unsigned char sub[BUFFER];
        err += bn_sub("0", mul, mul);
        err += bn_add(r_s, mul, sub);
        err += bn_mod(sub, g_globals.g_q, s_s);
    */

    /*  
     *  Server  →   (Y, sigma)      →   Client
     *         (aka_clientProofVerify)
     *  Server  ←   (tau_c, kappa)  ←   Client
     */
    err += aka_clientProofVerify(Y, &signature, &client);
    if(strcmp(client.tau_c, "0") == 0) {
        strcpy(server->tau_s, "0");
        free(client.signature);
        return 0;
    }

    strcpy(client.signature->r, signature.r);
    strcpy(server->kappa, "1");
    unsigned char ver[BUFFER];
    sprintf(ver, "%d", schnorr_verify(g_globals.params, g_aka_clientKeys.keys->pk, Y, server->kappa, client.signature));
    strcpy(server->tau_s, ver);

    /*
        unsigned char t_chck_1[BUFFER];
        err += bn_modexp(g_globals.g_g, client.pi[1], g_globals.g_q, t_chck_1);
        unsigned char t_chck_2[BIG_BUFFER];
        err += bn_modexp(pk_c, client.pi[0], g_globals.g_q, t_chck_2);
        unsigned char t_chck[BIG_BUFFER];
        err += bn_modmul(t_chck_1, t_chck_2, g_globals.g_q, t_chck);
        err += bn_modexp(t_chck, r_s, g_globals.g_q, server->kappa);
        
        unsigned char digest[BUFFER];
        err += hash(digest, Y, t_chck, server->kappa);

        if (strcmp(client.pi[0], digest) == 0) {
            strcpy(server->tau_s, "1");
        }
        else {
            strcpy(server->tau_s, "0");
        }
    */

    if(strcmp(server->kappa, client.kappa) == 0)
        printf(":)\n");
    
    free(client.signature);
    if (err != 2)
        return 0;
    return 1;
}

unsigned int aka_clientProofVerify (unsigned char *Y, struct SchnorrSignature *server_signature, struct ClientProof *client) {
    unsigned char ver[BUFFER];
    sprintf(ver, "%d", schnorr_verify(g_globals.params, g_aka_serverKeys.keys->pk, Y, "0", server_signature));
    strcpy(client->tau_c, ver);
    /*
        unsigned char t_s_chck_1[BUFFER];
        err += bn_modexp(g_globals.g_g, s_s, g_globals.g_q, t_s_chck_1);
        unsigned char t_s_chck_2[BUFFER];
        err += bn_modexp(pk_s, e_s, g_globals.g_q, t_s_chck_2);
        unsigned char t_s_chck[BUFFER];
        err += bn_modmul(t_s_chck_1, t_s_chck_2, g_globals.g_q, t_s_chck);
        
        unsigned char digest[BUFFER];
        err += hash(digest, Y, t_s_chck, "0");
    */

    if (strcmp(client->tau_c, "0") == 0) {
        return 0;
    }

    strcpy(client->kappa, "1");
    strcpy(client->signature->c_prime, server_signature->c_prime);
    unsigned int err = schnorr_sign(g_globals.params, g_aka_clientKeys.keys->sk, Y, client->kappa, client->signature);
    /*
    unsigned char r_c[BUFFER];
    unsigned char *rnd = malloc(sizeof(unsigned int));
    err += random_str_num_in_range(rnd, G_MAXRANDOMNUMBER, G_MINRANDOMNUMBER);
    err += bn_mod(rnd, g_globals.g_q, r_c);
    free(rnd);

    unsigned char t[BUFFER];
    err += bn_modexp(g_globals.g_g, r_c, g_globals.g_q, t);

    err += bn_modexp(t_s_chck, r_c, g_globals.g_q, client->kappa);
    err += hash(client->pi[0], Y, t, client->kappa);    //e_c

    unsigned char mul[BUFFER];
    err += bn_modmul(client->pi[0], sk_c, g_globals.g_q, mul);
    unsigned char sub[BUFFER];
    err += bn_sub("0", mul, mul);
    err += bn_add(r_c, mul, sub);
    err += bn_mod(sub, g_globals.g_q, client->pi[1]);             //s_c
    */
    
    return err;
}

/*  Support function definition
 *  print to console the keychain variables
 */

void _aka_keyPrinter(struct aka_Keychain *key) {
    printf("ID: %s\n", key->ID);
    printf("PK: %s\n", key->keys->pk);
    printf("SK: %s\n", key->keys->sk);
    
    return;
}

void free_aka_mem() {
    free(g_globals.params);
    free(g_aka_clientKeys.keys);
    free(g_aka_serverKeys.keys);

    return;
}