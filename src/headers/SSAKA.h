#ifndef __SSAKA_H__
#define __SSAKA_H__

struct Share {
    unsigned int pk_c_dash;
    unsigned int pk_c;
    unsigned int sk_c;
};

struct Device {
    unsigned int s_i;
    unsigned int kappa_i;
};

struct Share ssaka_ClientAddShare(unsigned int sk_new[][2], unsigned int sk_c, unsigned int pk_c);
struct Share ssaka_ClientRevShare(unsigned int sk_rev[][2], unsigned int sk_c, unsigned int pk_c);
struct ClientProof ssaka_ClientProofVerify(unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);
struct Device ssaka_DeviceProof(unsigned int t_s_chck, unsigned int sk_i);

#endif