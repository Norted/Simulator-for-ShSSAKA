#ifndef __AKA_H__
#define __AKA_H__

// extern headers
#include <globals.h>
#include <schnorrs_signature.h>

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int aka_setup();
unsigned int aka_initKeys(struct aka_Keychain *keys);
unsigned int aka_serverSignVerify (unsigned char * Y, struct ServerSign *server);
unsigned int aka_clientProofVerify (unsigned char *Y, struct SchnorrSignature *server_signature, struct ClientProof *client);
void free_aka_mem();

#endif