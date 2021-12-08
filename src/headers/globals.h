#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <openssl_bn.h>

#define G_NUMOFDEVICES      5
#define G_POLYDEGREE        2
#define G_GENERATORSLEN     6
#define G_MAXRANDOMNUMBER   100
#define G_MINRANDOMNUMBER   1
#define BITS                32
#define BUFFER              BITS*4
#define BIG_BUFFER          BITS*32
#define BUFFER100           100

struct ServerSign {
    unsigned char tau_s[BUFFER];
    unsigned char kappa[BIG_BUFFER];
};

struct ClientProof {
    unsigned char tau_c[BUFFER];
    unsigned char pi[2][BUFFER];
    unsigned char kappa[BUFFER];
};

struct DeviceProof {
    unsigned char s_i[BUFFER];
    unsigned char kappa_i[BUFFER];
};

/*  === GLOBALS ===
 *  ||---> g_q ................. order of multiplicative group Z*_q
 *  ||---> g_g ................. generated generator from g_generators
 *  ||---> g_idCounter ......... helping couter for CID generation
 */

struct globals {
    unsigned char g_q[BUFFER];
    unsigned char g_g[BUFFER];
    unsigned int g_idCounter;
};

extern struct globals g_globals;

void init_g_global();
unsigned int schnorr_group(unsigned char *g, unsigned char *q);

#endif