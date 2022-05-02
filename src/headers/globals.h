#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#define G_NUMOFDEVICES      10
#define G_POLYDEGREE        2
#define G_GENERATORSLEN     6
#define G_MAXRANDOMNUMBER   100
#define G_MINRANDOMNUMBER   1
#define BITS                256
#define BUFFER              BITS*4
#define BIG_BUFFER          BITS*32
#define BUFFER100           100
#define MAXITER             10000
#define RANGE               100//000
#define NUM_THREADS         2

// LIBRARIES
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl_bn.h>
#include <cjson/cJSON.h>

// PAilLIER
struct paillierPrivateKey {
    unsigned char l[BUFFER];
    unsigned char m[BUFFER];
};

struct paillierPublicKey {
    unsigned char n[BUFFER];
    unsigned char n_sq[BUFFER];
    unsigned char g[BUFFER];
};

struct paillierKeychain {
    struct paillierPrivateKey sk;
    struct paillierPublicKey pk;
};

// SCHNORR SIGNATURE
struct SchnorrParams {
    unsigned char p[BUFFER];
    unsigned char q[BUFFER];
    unsigned char g[BUFFER];
};

struct SchnorrSignature {
    unsigned char hash[BUFFER];
    unsigned char signature[BUFFER];
    unsigned char r[BUFFER];
    unsigned char c_prime[BUFFER];
};

struct SchnorrKeychain {
    unsigned char pk[BUFFER];
    unsigned char sk[BUFFER];
};

// AKA
struct aka_Keychain {
    struct SchnorrKeychain *keys;
    unsigned char ID[BUFFER];
};

// SSAKA
struct ssaka_Keychain {
    unsigned char ID[BUFFER];
    struct SchnorrKeychain *keys;
    unsigned char kappa[BUFFER];
};

// OTHERS
struct ServerSign {
    unsigned char tau_s[BUFFER];
    unsigned char kappa[BIG_BUFFER];
};

struct ClientProof {
    unsigned char tau_c[BUFFER];
    struct SchnorrSignature *signature;
    unsigned char kappa[BUFFER];
};

struct DeviceProof {
    unsigned char s_i[BUFFER];
    unsigned char kappa_i[BUFFER];
};

/*  === GLOBALS ===
 *  ||---> params .............. Schnorr's Signature struct with p, q, g params
 *  ||---> g_idCounter ......... helping couter for CID generation
 */

struct globals {
    struct SchnorrParams *params;
    unsigned int idCounter;
};

extern struct globals g_globals;
extern struct paillierKeychain p_keyring;
extern DSA *dsa;
extern pthread_t threads[];

// AKA
extern struct aka_Keychain g_aka_serverKeys;
extern struct aka_Keychain g_aka_clientKeys;
// SSAKA
extern struct aka_Keychain g_ssaka_serverKeys;
extern struct ssaka_Keychain g_ssaka_devicesKeys[];
extern struct paillierKeychain g_paiKeys;
extern unsigned int currentNumberOfDevices;
extern unsigned char pk_c[BUFFER];


#endif