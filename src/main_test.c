#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
// local headers
#include <globals.h>
#include <schnorrs_signature.h>
#include <paillier_scheme.h>
#include <support_functions.h>
#include <paishamir.h>
#include <AKA.h>
#include <ShSSAKA.h>

// Keychains
struct aka_Keychain g_serverKeys;
struct aka_Keychain g_aka_clientKeys;
extern struct ssaka_Keychain g_ssaka_devicesKeys[G_NUMOFDEVICES];

struct paillier_Keychain g_paiKeys;
EC_POINT *pk_c;

// Globals
BIGNUM *g_range;
struct globals g_globals;
unsigned int currentNumberOfDevices = G_NUMOFDEVICES;

// Threding and pre-computation globals
unsigned int paillier_inited = 0;
unsigned int pre_noise = 0;
unsigned int pre_message = 0;

// File names
const char *restrict file_keychain = "keychain.json";
const char *restrict file_precomputed_noise = "precomputed_values/precomputation_noise.json";
const char *restrict file_precomputed_message = "precomputed_values/precomputation_message.json";

// Benchmarking
clock_t start, finish, dev_start, dev_finish, s_start, s_finish;
double consumed_time, dev_consumed_time, s_consumed_time;

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
    err = gen_schnorr_keychain(group, g_globals.keychain);
   
    
    
    printf("\n--- BENCHMARKING ---\n");

    FILE *file = fopen("../benchmarks/poly_10.csv", "w");
    if (file == NULL)
    {
        printf("\t * File open failed!\n");
        return 0;
    }

    /* unsigned int list_of_all_devs[currentNumberOfDevices - 1];
    for (int i = 1; i < currentNumberOfDevices; i++)
    {
        list_of_all_devs[i - 1] = i;
    }
    unsigned int size_all = sizeof(list_of_all_devs) / sizeof(unsigned int); */

    int upper = currentNumberOfDevices-1;
    int lower_devs = 1;
    int iter = 10;

    struct ServerSign server;
    
    fprintf(file, "SETUP\nNUM_THREADS;%d\nG_NUMOFDEVICES;%d\nG_POLYDEGREE;%d\nBUFFER;%d\nBITS;%d\nMAXITER;%d\nRANGE;%d\n\nShSSAKA_SETUP\nITER;DEV_GEN;SERV_GEN;TIME;ERR\n",
            NUM_THREADS, G_NUMOFDEVICES, G_POLYDEGREE, BUFFER, BITS, MAXITER, RANGE);
    
    for(int i = 0; i < iter; i++)
    {
        printf("Round %d\t", i);
        start = clock();
            if(paillier_inited == 0)
            {
                init_paillier_keychain(&g_paiKeys);
                err = paillier_generate_keypair(&g_paiKeys);
            }
            pk_c = EC_POINT_new(g_globals.keychain->ec_group);

            dev_start = clock();
                int i = 0;
                for (i; i < currentNumberOfDevices; i++)
                {
                    g_ssaka_devicesKeys[i].pk = BN_new();
                    g_ssaka_devicesKeys[i].sk = BN_new();
                    g_ssaka_devicesKeys[i].kappa = BN_new();

                    err = ssaka_KeyGeneration(&g_ssaka_devicesKeys[i]);
                }
                err = paiShamir_distribution(&g_paiKeys);
            dev_finish = clock();
            dev_consumed_time = difftime(dev_finish, dev_start);

            s_start = clock();
                err = _get_pk_c();
                init_aka_mem(&g_serverKeys);
            s_finish = clock();
            s_consumed_time = difftime(s_finish, s_start);
        finish = clock();
        consumed_time = difftime(finish, start);
        fprintf(file, "%d;%f;%f;%f;%d\n", i, (dev_consumed_time/CLOCKS_PER_SEC), (s_consumed_time/CLOCKS_PER_SEC), (consumed_time/CLOCKS_PER_SEC), err);
        printf("Finished! ~ %d\n", err);
    }

    fprintf(file, "\nShSSAKA_VERIFY\nITER;N#DEV;AUTH_TIME;VER_TIME;ERR\n");
    
    for (int i = 0; i < iter; i++)
    {
        printf("Round %d\n", i);
        for (int z = G_POLYDEGREE; z < currentNumberOfDevices; z++)
        {
            init_serversign(g_globals.keychain->ec_group, &server);
            unsigned int list_of_used_devs[z];
            for (int j = 0; j < z; j++)
            {
            again:
                list_of_used_devs[j] = (rand() % (upper - lower_devs + 1)) + lower_devs;
                for(int u = 0; u < j; u++)
                    if(list_of_used_devs[j] == list_of_used_devs[u])
                        goto again;
                printf("%d ", list_of_used_devs[j]);
            }
            printf("\t");

            pre_message = 1;
            pre_noise = 1;    

            err = ssaka_akaServerSignVerify(list_of_used_devs, z, message, &server);

            fprintf(file, "%d;%d;%f;%f;%d\n", i, z, (g_auth_consumed_time/CLOCKS_PER_SEC), (g_ver_consumed_time/CLOCKS_PER_SEC), err);

            free_serversign(&server);
        }
    }

end:
    printf("\n\nRETURN_CODE: %u\n", return_code);

    free_ssaka_mem();
    free_schnorr_keychain(g_globals.keychain);
    free(g_globals.keychain);
    EC_GROUP_free(group);
    BN_free(message);
    free(tmp_str);
    BN_free(g_range);

    return return_code;
}
