#ifndef __SSAKA_H__
#define __SSAKA_H__

int ssaka_ClientAddShare(unsigned int sk_new[], unsigned int sk_c, unsigned int pk_c);
int ssaka_ClientRevShare(unsigned int sk_rev[], unsigned int sk_c, unsigned int pk_c);
int ssaka_ClientProofVerify(unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c);
int ssaka_DeviceProof(unsigned int t_s_chck, unsigned int sk_i);

#endif