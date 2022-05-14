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
unsigned int currentNumberOfDevices = 4;

// Threding and pre-computation globals
unsigned int paillier_inited = 0;
unsigned int pre_noise = 0;
unsigned int pre_message = 0;

// File names
const char *restrict file_keychain = "keychain.json";
const char *restrict file_precomputed_noise = "precomputed_values/precomputation_noise.json";
const char *restrict file_precomputed_message = "precomputed_values/precomputation_message.json";

// Benchmarking
clock_t start, finish;
double consumed_time, average_time;

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
    unsigned int list_of_all_devs[currentNumberOfDevices - 1];
    for (int i = 1; i < currentNumberOfDevices; i++)
    {
        list_of_all_devs[i - 1] = i;
    }
    unsigned int size_all = sizeof(list_of_all_devs) / sizeof(unsigned int);

    int upper = currentNumberOfDevices-1;
    int lower_devs = 0;

    struct ServerSign server;
    
    start = clock();
        err = ssaka_setup();
    finish = clock();
    consumed_time = difftime(finish, start);
    
    for (int i = 0; i < 100; i++)
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

            // pre_message = 1;
            // pre_noise = 1;    

            start = clock();
                err = ssaka_akaServerSignVerify(list_of_all_devs, size_all, message, &server);
            finish = clock();
            consumed_time = difftime(finish, start);

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