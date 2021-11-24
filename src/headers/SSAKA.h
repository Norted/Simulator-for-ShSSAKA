#ifndef __SSAKA_H__
#define __SSAKA_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <string.h>
// extern headers
#include <polynomial.h>
#include <paillier.h>
#include <openssl/sha.h>

// structures definition
struct aka_Keychain {
    unsigned int pk;
    unsigned int sk;
    unsigned int ID;
};

struct ServerSign {
    unsigned int tau_s;
    unsigned int kappa;
};

struct ClientProof {
    unsigned int tau_c;
    unsigned int pi[2];
    unsigned int kappa;
};

struct DeviceProof {
    unsigned int s_i;
    unsigned int kappa_i;
};

struct ssaka_Keychain {
    unsigned int ID;
    unsigned long long pk;
    unsigned long long sk;
    unsigned long long d_1;
    unsigned long long d_2;
    unsigned long long kappa;
};

struct Share {
    unsigned int pk_c_dash;
    unsigned int pk_c;
    unsigned int sk_c;
};

/*  --- GLOBALS ---
 *  |-> g_q ................. order of multiplicative group Z*_q
 *  |-> g_g ................. generated generator from g_generators
 *  |-> g_generators ........ hardcoded generators of Z*_q
 *  |-> g_idCounter ......... helping couter for CID generation
 *  ------ support globals
 *      |-> g_generatorsLen ..... length of the g_generators field 
 *      |-> g_maxRandomNumber ... maximal random number
 *      |-> g_minRandomNumber ... minimal random number
 */

extern const unsigned int g_q;
extern unsigned int g_g;
extern const unsigned int g_generators[];
extern unsigned int g_idCounter;

extern const int g_generatorsLen;
extern const int g_maxRandomNumber;
extern const int g_minRandomNumber;

#define G_NUMOFDEVICES  5

extern struct aka_Keychain g_aka_serverKeys;
extern struct aka_Keychain g_aka_clientKeys;
extern struct aka_Keychain g_aka_devicesKeys[];

extern struct ssaka_Keychain ssaka_deviceKeys[];

#define LEN(arr) ((int) (sizeof (arr) / sizeof (arr)[0]))

// AKA /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
void setup();

struct ServerSign aka_serverSignVerify (unsigned int Y, unsigned int pk_s, unsigned int sk_c);
struct ClientProof aka_clientProofVerify (unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);

// SSAKA ///////////////////////////////////////////////////////////////////////////////////////////////////////////////

void ssaka_KeyGeneration(struct ssaka_Keychain *ssaka_Keychain);
unsigned long long ssaka_ShamirKeyComputation();
unsigned long long ssaka_PaillierEncryption(struct ssaka_Keychain *ssaka_Keychain, struct paillierKeyring paiKeys);
struct Share ssaka_ClientAddShare(unsigned int sk_new[][2], unsigned int sk_c, unsigned int pk_c);
//struct Share ssaka_ClientRevShare(unsigned int sk_rev[][2], unsigned int sk_c, unsigned int pk_c);
struct ClientProof ssaka_ClientProofVerify(unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);
struct DeviceProof ssaka_DeviceProof(unsigned int t_s_chck, unsigned int sk_i);
unsigned long long calculateSHA(unsigned char *hash, unsigned int Y, unsigned int t_s, unsigned int kappa);
unsigned long long hex_to_int(unsigned char *hex);

#endif