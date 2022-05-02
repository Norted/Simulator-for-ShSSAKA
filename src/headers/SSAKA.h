#ifndef __SSAKA_H__
#define __SSAKA_H__

// extern headers
#include <AKA.h>
#include <paillier.h>
#include <paishamir.h>
#include <globals.h>

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int ssaka_setup();
unsigned int ssaka_KeyGeneration(struct ssaka_Keychain *ssaka_Keychain);
unsigned int ssaka_ClientAddShare(unsigned int num_of_new_devices);
unsigned int ssaka_ClientRevShare(unsigned int rev_devices_list[], unsigned int list_size);
unsigned int ssaka_akaServerSignVerify(unsigned int list_of_used_devs[], unsigned int size, unsigned char * Y, struct ServerSign *server);
unsigned int ssaka_clientProofVerify(unsigned int list_of_used_devs[], unsigned int size, unsigned char *Y, struct SchnorrSignature *server_signature, struct ClientProof *client);
//unsigned int ssaka_DeviceProof(unsigned char *t_s_chck, unsigned char *sk_i, struct DeviceProof *device);
void ssaka_keyPrinter(struct ssaka_Keychain *key);
void free_ssaka_mem();

#endif