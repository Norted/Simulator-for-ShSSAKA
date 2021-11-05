#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "AKA.h"
// #include "headers/SSAKA.h"


/////////////////////////////////////////////////////////////////////
// MAIN /////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
int main(){
    unsigned int Y = 100;
    struct SERVER_SIGN server;
    
    /*  AKA-SETUP and AKA-CLIENT-REGISTER
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for client and server side
     */
    aka_setup();
    
    /*  AKA-SERVER-SIGNVERIFY(Y, sk_s, pk_c)
     *      Y, sigma    →   AKA-CLIENT-PROOFVERIFY(Y, sigma)
     *                  ←   tau_c (value 0/1), pi, kappa
     *      tau_s (value 0/1), kappa
     */
    server = aka_server_signverify(Y, SERVER_KEYS.sk, CLIENT_KEYS.pk);
    if (server.tau_s == 0) {
        printf("TAU_S = %d\nProtocol ends.\n", server.tau_s);
        return -1;
    }
    else {
        printf("TAU_S = %d\nProtocol continues.\n", server.tau_s);
    }
    
    return 0;
}

/* RESOURCES
 *
 *  https://math.stackexchange.com/questions/814879/find-a-generator-of-the-multiplicative-group-of-mathbbz-23-mathbbz-as-a-c
 *  https://stackoverflow.com/questions/23360728/how-to-generate-a-number-of-n-bit-in-length
 *  https://stackoverflow.com/questions/2844/how-do-you-format-an-unsigned-long-long-int-using-printf
 */