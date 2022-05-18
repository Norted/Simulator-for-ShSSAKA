#ifndef __SHSSAKA_H__
#define __SHSSAKA_H__

// extern headers
#include <support_functions.h>
#include <schnorrs_signature.h>
#include <paishamir.h>
#include <paillier_scheme.h>
#include <AKA.h>
#include <globals.h>

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int shssaka_setup();
unsigned int shssaka_KeyGeneration(struct shssaka_Keychain *shssaka_Keychain);
unsigned int shssaka_ClientAddShare(unsigned int num_of_new_devices);
unsigned int shssaka_ClientRevShare(unsigned int *rev_devices_list, unsigned int list_size);
unsigned int shssaka_akaServerSignVerify(unsigned int *list_of_used_devs, unsigned int size, BIGNUM * Y, struct ServerSign *server);
unsigned int shssaka_clientProofVerify(unsigned int *list_of_used_devs, unsigned int size, BIGNUM *Y, struct schnorr_Signature *server_signature, struct ClientProof *client);
// unsigned int shssaka_DeviceProof(BIGNUM *t_s_chck, BIGNUM *sk_i, struct DeviceProof *device);
void init_shssaka_mem();
void free_shssaka_mem();
void shssaka_keyPrinter(struct shssaka_Keychain *key);

#endif