#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#define NUM_THREADS 4
#define G_NUMOFDEVICES 10
#define G_POLYDEGREE 2
#define G_GENERATORSLEN 6
#define G_MAXRANDOMNUMBER 100
#define G_MINRANDOMNUMBER 1
#define BUFFER 512 // 512, 1024
#define BITS 512   // 512, 1024, 1500, 2048
#define MAXITER 10000

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/dsa.h>
#include <cjson/cJSON.h>
#include <AKA.h>
#include <SSAKA.h>
#include <schnorrs_signature.h>
#include <paillier_scheme.h>
#include <paishamir.h>
#include <support_functions.h>

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

/*  === GLOBALS ===
 *  ||---> params .............. Schnorr's Signature struct with p, q, g params
 *  ||---> g_idCounter ......... helping couter for CID generation
 */

struct globals
{
    struct schnorr_Params *params;
    unsigned int idCounter;
};

extern struct globals g_globals;

#endif