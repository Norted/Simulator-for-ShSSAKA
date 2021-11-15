#ifndef __SSAKA_H__
#define __SSAKA_H__


// structures definition
struct Keychain {
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
 *      |-> g_generatosrLen ..... length of the g_generators field 
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

#define G_NUMOFDEVICES 3

extern struct Keychain g_clientKeys;
extern struct Keychain g_serverKeys;
extern struct Keychain g_devicesKeys[];

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
void setup();

struct ServerSign aka_serverSignVerify (unsigned int Y, unsigned int pk_s, unsigned int sk_c);
struct ClientProof aka_clientProofVerify (unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);
struct Share ssaka_ClientAddShare(unsigned int sk_new[][2], unsigned int sk_c, unsigned int pk_c);
struct Share ssaka_ClientRevShare(unsigned int sk_rev[][2], unsigned int sk_c, unsigned int pk_c);
struct ClientProof ssaka_ClientProofVerify(unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);
struct DeviceProof ssaka_DeviceProof(unsigned int t_s_chck, unsigned int sk_i);

#endif