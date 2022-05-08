#ifndef __GLOBALS_H__
#define __GLOBALS_H__

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
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <cjson/cJSON.h>

// ======== STRUCTS =====================================================================
// SCHNORR STRUCTS
struct schnorr_Params
{
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
};

struct schnorr_Signature
{
    BIGNUM *hash;
    BIGNUM *signature;
    BIGNUM *r;
    BIGNUM *c_prime;
};

struct schnorr_Keychain
{
    BIGNUM *pk;
    BIGNUM *sk;
};

// EC SCHNORR STRUCTS
struct EC_schnorr_Params
{
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
};

struct EC_schnorr_Signature
{
    BIGNUM *hash;
    BIGNUM *signature;
    BIGNUM *r;
    BIGNUM *c_prime;
};

struct EC_schnorr_Keychain
{
    BIGNUM *pk;
    BIGNUM *sk;
};

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
    BIGNUM *kappa;
};

struct ClientProof
{
    BIGNUM *tau_c;
    struct schnorr_Signature *signature;
    BIGNUM *kappa;
};

struct DeviceProof
{
    BIGNUM *s_i;
    BIGNUM *kappa_i;
};

// AKA STRUCTS
struct aka_Keychain
{
    struct schnorr_Keychain *keys;
    unsigned int ID;
};

// SSAKA STRUCTS
struct ssaka_Keychain
{
    unsigned int ID;
    struct schnorr_Keychain *keys;
    BIGNUM *kappa;
};

// GLOBALS STRUCT
struct globals
{
    struct schnorr_Params *params; // Schnorr's Signature struct with p, q, g params
    unsigned int idCounter;        // helping couter for CID generation
};

// ======== EXTERNS =====================================================================
extern struct globals g_globals;
extern unsigned int currentNumberOfDevices;
extern DSA *dsa;

// SSAKA globals
extern struct ssaka_Keychain g_ssaka_devicesKeys[];
extern struct paillier_Keychain g_paiKeys;
extern BIGNUM *pk_c;

// AKA globals
extern struct aka_Keychain g_serverKeys;
extern struct aka_Keychain g_aka_clientKeys;

// Threding and pre-computation
pthread_t threads[NUM_THREADS];
extern BIGNUM *range;
extern unsigned int pre_noise;
extern unsigned int pre_message;
extern const char *restrict file_precomputed_noise;
extern const char *restrict file_precomputed_message;
cJSON *json_noise;
cJSON *json_message;

#endif