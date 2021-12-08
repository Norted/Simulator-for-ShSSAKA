#ifndef __SSAKA_H__
#define __SSAKA_H__

// extern headers
#include <AKA.h>
#include <globals.h>
#include <paillier.h>

// structures definition
struct ssaka_Keychain {
    unsigned char ID[BUFFER];
    unsigned char pk[BUFFER];
    unsigned char sk[BUFFER];
    unsigned char ds[G_POLYDEGREE][BUFFER];
    unsigned char kappa[BUFFER];
};

struct Share {
    unsigned char new_pk_c[BUFFER];
    unsigned char new_sk_c[BUFFER];
};

extern struct aka_Keychain g_ssaka_serverKeys;
extern struct ssaka_Keychain g_ssaka_deviceKeys[];

extern struct paillierKeychain g_paiKeys;

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
unsigned int ssaka_setup();
unsigned int ssaka_KeyGeneration(struct ssaka_Keychain *ssaka_Keychain);
unsigned int ssaka_ShamirKeyComputation(unsigned char *key, unsigned int device_ID);
unsigned int ssaka_PaillierEncryption(struct ssaka_Keychain *ssaka_Keychain, unsigned char *ci);
unsigned int ssaka_interpolation (unsigned char *interpolation, unsigned int device);
unsigned int ssaka_ClientAddShare(unsigned int new_devices_list[], unsigned int list_size, unsigned char *sk_c, unsigned char *pk_c_old, struct Share *share);
//unsigned int ssaka_ClientRevShare(unsigned int *rev_devices_list, unsigned char *sk_c, unsigned char *pk_c, struct Share *share);
unsigned int ssaka_akaServerSignVerify(unsigned int list_of_used_devs[], unsigned int size, unsigned char * Y, unsigned char * pk_c, unsigned char * sk_s, struct ServerSign *server);
unsigned int ssaka_ClientProofVerify(unsigned int list_of_used_devs[], unsigned int size, unsigned char *Y, unsigned char *e_s, unsigned char *s_s, unsigned char *pk_s, unsigned char *sk_c, struct ClientProof *client);
//unsigned int ssaka_DeviceProof(unsigned char *t_s_chck, unsigned char *sk_i, struct DeviceProof *device);

#endif