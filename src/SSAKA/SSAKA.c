#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
// extern libs
#include <polynomial.h>
#include <gcrypt.h>
// local libs
#include <AKA.h>
#include <SSAKA.h>


// supportive functions declarations
unsigned int _encrypt(unsigned int sk, unsigned int mod);

// globals
int g_maxRandomNumber = 100;
int g_minRandomNumber = 1;

struct Share ssaka_ClientAddShare(unsigned int sk_new[][2], unsigned int sk_c, unsigned int pk_c) {
    struct Share share;

    unsigned int poly_degree = 2;
    unsigned int poly_coefs[3] = {0, 0, 0};
    Polynomial *poly = polynomial_new(poly_degree);
    for (int i = 0; i < poly_degree; i++) {
        poly_coefs[0] += sk_new[i][1];
        poly_coefs[1] += sk_new[i][0] % 2;
        poly_coefs[2] += sk_new[i][0] - (sk_new[i][0] % 2);
    }
    polynomial_set_coefficient(poly, 0, poly_coefs[0]);
    polynomial_set_coefficient(poly, 1, poly_coefs[1]);
    polynomial_set_coefficient(poly, 2, poly_coefs[2]);

    int size = sizeof(sk_new) / sizeof(sk_new[0]);
    for (int i = 0; i < size; i++) {
        // TODO
    }
    return share;
}

struct Share ssaka_ClientRevShare(unsigned int sk_rev[][2], unsigned int sk_c, unsigned int pk_c) {
    struct Share share;
    
    int size = sizeof(sk_rev) / sizeof(sk_rev[0]);
    for (int i = 0; i < size; i++) {
        // TODO
    }
    return share;
}

struct ClientProof ssaka_ClientProofVerify(unsigned int Y, unsigned int sigma[2], unsigned int pk_s, unsigned int sk_c) {
    struct ClientProof client;
    
    return client;
}

struct Device ssaka_DeviceProof(unsigned int t_s_chck, unsigned int sk_i) {
    struct Device device;

    return device;
}

unsigned int _encrypt(unsigned int sk, unsigned int mod) {
    srand(3);
    return 0;
}