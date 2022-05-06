#ifndef __SSAKA_H__
#define __SSAKA_H__

// extern headers
#include <support_functions.h>
#include <schnorrs_signature.h>
#include <paishamir.h>
#include <paillier_scheme.h>
#include <AKA.h>
#include <globals.h>

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int ssaka_setup();
unsigned int ssaka_KeyGeneration(struct ssaka_Keychain *ssaka_Keychain);
unsigned int ssaka_ClientAddShare(unsigned int num_of_new_devices);
unsigned int ssaka_ClientRevShare(unsigned int *rev_devices_list, unsigned int list_size);
unsigned int ssaka_akaServerSignVerify(unsigned int *list_of_used_devs, unsigned int size, BIGNUM * Y, struct ServerSign *server);
unsigned int ssaka_clientProofVerify(unsigned int *list_of_used_devs, unsigned int size, BIGNUM *Y, struct schnorr_Signature *server_signature, struct ClientProof *client);
// unsigned int ssaka_DeviceProof(BIGNUM *t_s_chck, BIGNUM *sk_i, struct DeviceProof *device);
void init_ssaka_mem();
void free_ssaka_mem();
void ssaka_keyPrinter(struct ssaka_Keychain *key);

#endif