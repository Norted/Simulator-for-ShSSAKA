#ifndef __AKA_H__
#define __AKA_H__

// extern headers
#include <globals.h>


// structures definition
struct aka_Keychain {
    struct schnorr_Keychain *keys;
    unsigned int ID;
};

extern struct aka_Keychain g_aka_serverKeys;
extern struct aka_Keychain g_aka_clientKeys;


// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int aka_setup();
unsigned int aka_initKeys(struct aka_Keychain *keys);
unsigned int aka_serverSignVerify (BIGNUM * Y, struct ServerSign *server);
unsigned int aka_clientProofVerify (BIGNUM *Y, struct schnorr_Signature *server_signature, struct ClientProof *client);
void free_aka_mem();

#endif