#ifndef __AKA_H__   /* Include guard */
#define __AKA_H__

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

// globals
extern struct Keychain g_clientKeys;
extern struct Keychain g_serverKeys;

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
void aka_setup();

struct ServerSign aka_serverSignVerify (unsigned int Y, unsigned int pk_s, unsigned int sk_c);
struct ClientProof aka_clientProofVerify (unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);

#endif