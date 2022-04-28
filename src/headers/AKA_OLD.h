#ifndef __AKA_H__
#define __AKA_H__

// extern headers
#include <support_functions.h>
#include <schnorrs_signature_OLD.h>
#include <globals.h>

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int aka_setup();
unsigned int aka_serverSignVerify(BIGNUM *Y, struct ServerSign *server);
unsigned int aka_clientProofVerify(BIGNUM *Y, struct schnorr_Signature *server_signature, struct ClientProof *client);
void init_aka_mem(struct aka_Keychain *keychain);
void free_aka_mem(struct aka_Keychain *keychain);
void aka_keyPrinter(struct aka_Keychain *key);

#endif