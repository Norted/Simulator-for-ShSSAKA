#ifndef __AKA_H__   /* Include guard */
#define __AKA_H__

// structures definition
struct KEYCHAIN {
    unsigned int pk;
    unsigned int sk;
    unsigned int ID;
};

struct SERVER_SIGN {
    unsigned int tau_s;
    unsigned int kappa;
};

struct CLIENT_PROOF {
    unsigned int tau_c;
    unsigned int pi[2];
    unsigned int kappa;
};

// globals
extern struct KEYCHAIN CLIENT_KEYS;
extern struct KEYCHAIN SERVER_KEYS;

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
void aka_setup();

struct SERVER_SIGN aka_server_signverify (unsigned int Y, unsigned int pk_s, unsigned int sk_c);
struct CLIENT_PROOF aka_client_proofverify (unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);

#endif