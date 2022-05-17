#ifndef __GLOBALS_EC_H__
#define __GLOBALS_EC_H__

// ======== MACROS ======================================================================
#define NUM_THREADS 2
#define G_NUMOFDEVICES 10
#define G_POLYDEGREE 2
#define BUFFER 512 // 512, 1024
#define BITS 512   // 512, 1024, 1500, 2048
#define MAXITER 10000
#define RANGE 1000

// ======== COMMON LIBRARIES ============================================================
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <cJSON.h>

// ======== STRUCTS =====================================================================
// PAILLIER STRUCTS
struct paillier_PrivateKey
{
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *lambda;
    BIGNUM *mi; // modular multiplicative inverse (L(g^lambda mod n^2))^(-1) mod n
};

struct paillier_PublicKey
{
    BIGNUM *n;
    BIGNUM *n_sq;
    BIGNUM *g;
};

struct paillier_Keychain
{
    struct paillier_PrivateKey *sk;
    struct paillier_PublicKey *pk;
};

// SIGNS & PROOFS STRUCTS
struct ServerSign
{
    BIGNUM *tau_s;
    EC_POINT *kappa;
};

struct ClientProof
{
    BIGNUM *tau_c;
    struct schnorr_Signature *signature;
    EC_POINT *kappa;
};

struct DeviceProof
{
    BIGNUM *s_i;
    const EC_POINT *kappa_i;
};

// SCHNORR STRUCTS
struct schnorr_Keychain
{
    const EC_GROUP *ec_group;
    const EC_KEY *keys;
};

struct schnorr_Signature
{
    BIGNUM *hash;
    BIGNUM *signature;
    BIGNUM *r;
    EC_POINT *c_prime;
};

// AKA STRUCT
struct aka_Keychain
{
    struct schnorr_Keychain *keys;
    unsigned int ID;
};

// SSAKA STRUCT
struct ssaka_Keychain
{
    unsigned int ID;
    BIGNUM *sk;
    BIGNUM *pk;
    BIGNUM *kappa;
};

// GLOBALS STRUCT
struct globals
{
    struct schnorr_Keychain *keychain;
    unsigned int idCounter;
};

// ======== EXTERNS =====================================================================
extern struct globals g_globals;
extern struct ssaka_Keychain g_ssaka_devicesKeys[];
extern struct aka_Keychain g_serverKeys;
extern struct aka_Keychain g_aka_clientKeys;
extern unsigned int currentNumberOfDevices;
extern struct paillier_Keychain g_paiKeys;
extern EC_POINT *pk_c;

// Threding and pre-computation
pthread_t threads[NUM_THREADS];
extern BIGNUM *g_range;
extern unsigned int paillier_inited;
extern unsigned int pre_noise;
extern unsigned int pre_message;
extern const char *restrict file_keychain;
extern const char *restrict file_precomputed_noise;
extern const char *restrict file_precomputed_message;
cJSON *json_noise;
cJSON *json_message;

#endif