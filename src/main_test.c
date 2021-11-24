#include <stdio.h>
#include <stdlib.h>
#include <math.h>
// local headers
#include <SSAKA.h>
#include <paillier.h>


int main(){
    //unsigned int Y = 100;
    //struct ServerSign server;

    /*  AKA-SETUP and AKA-CLIENT-REGISTER
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for devices, client and server side
     */
    //setup();
    
    /*  SSAKA-SERVER-SIGNVERIFY
     *
     *  SSAKA-CLIENT-PROOFVERIFY(Y, sigma, pk_s, sk_c)
     *
     *  AKA-SERVER-SIGNVERIFY(Y, sk_s, pk_c)
     *      Y, sigma    →   AKA-CLIENT-PROOFVERIFY(Y, sigma)
     *                  ←   tau_c (value 0/1), pi, kappa
     *      tau_s (value 0/1), kappa
     * 

        server = aka_serverSignVerify(Y, g_aka_serverKeys.sk, g_aka_clientKeys.pk);
        if (server.tau_s == 0) {
            printf("TAU_S = %d\nProtocol ends.\n", server.tau_s);
            return -1;
        }
        else {
            printf("TAU_S = %d\nProtocol continues.\n", server.tau_s);
        }
    */

    
    /* My PAILLIER test 

        printf("\n\n---PAILLIER test---\n");
        struct paillierKeyring p_keyring = generate_keypair();
        printf("KEYS:\n|-->PK: %llu\n|--> SK: %llu\n\n", p_keyring.pk, p_keyring.sk);
        
        for (int secret = 0; secret <= p_keyring.pk.n; secret++) {
            //printf("SECRET: %d\n", secret);
            unsigned long long enc = encrypt(p_keyring.pk, secret);
            //printf("ENC: %llu\n", enc);
            unsigned long long dec = decrypt(p_keyring, enc);
            //printf("DEC: %llu\n", dec);
            if(secret != dec) {
                printf("SECRET: %u\nDEC: %llu\n", secret, dec);
            }
        }
    */
    unsigned char result[41];
    int res = calculateSHA(result, 3, 4, 5);
    printf("%s\n", result);

    return 0;
}

/* --- RESOURCES ---
 *  https://math.stackexchange.com/questions/814879/find-a-generator-of-the-multiplicative-group-of-mathbbz-23-mathbbz-as-a-c
 *  https://stackoverflow.com/questions/23360728/how-to-generate-a-number-of-n-bit-in-length
 *  https://stackoverflow.com/questions/2844/how-do-you-format-an-unsigned-long-long-int-using-printf
 *  
 *  ~~~ WOLFSSL ~~~
 *  https://www.wolfssl.com/
 */