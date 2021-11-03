#ifndef __AKA_H__   /* Include guard */
#define __AKA_H__

// int SETUP (int kappa);
// int CLIENT_REGISTER (int kappa);
int SERVER_SIGNVERIFY (int Y, int pk_s, int sk_c);
int CLIENT_PROOFVERIFY (int Y, int sigma, int pk_s, int sk_c);

#endif