#ifndef __AKA_H__
#define __AKA_H__

// extern headers
#include <globals.h>
//#include <polynomial.h>


// structures definition
struct aka_Keychain {
    unsigned char pk[BUFFER];
    unsigned char sk[BUFFER];
    unsigned char ID[BUFFER];
};

extern struct aka_Keychain g_aka_serverKeys;
extern struct aka_Keychain g_aka_clientKeys;
extern struct aka_Keychain g_aka_devicesKeys[];


// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int aka_setup();
unsigned int aka_initKeys(struct aka_Keychain *keys);
unsigned int aka_serverSignVerify (unsigned char *Y, unsigned char *pk_c, unsigned char *sk_s, struct ServerSign *server);
unsigned int aka_clientProofVerify (unsigned char *Y, unsigned char *e_s, unsigned char *s_s, unsigned char *pk_s, unsigned char *sk_c, struct ClientProof *client);

#endif