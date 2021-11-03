#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <AKA.h>
#include <SSAKA.h>

/////////////////////////////////////////////////////////////////////
// SETUP ////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// keychain struct definition
struct Keychain {
    unsigned int pk;
    unsigned int sk;
    unsigned int ID;
};

// function headers
void key_printer(struct Keychain keys);
struct Keychain init_keys();

// globals
unsigned int MOD = 18;
unsigned int G = 0;
unsigned int GENERATORS[6] = {4, 7, 9, 10, 13, 16};
unsigned int ID_COUNTER = 1;

int generators_len = 5;
int max_number = 100;
int minimum_number = 1;

/////////////////////////////////////////////////////////////////////
// MAIN /////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
int main(){
    /*  AKA-SETUP and AKA-CLIENT-REGISTER
     *      1) randomly initialize generator from GENERATORS
     *      2) generate keys for client and server side
     */
    srand(3);
    G = GENERATORS[rand()%generators_len];
    
    struct Keychain client_keys = init_keys();
    struct Keychain server_keys = init_keys();

    /*  AKA-SERVER-SIGNVERIFY   */

    /*  AKA-CLIENT-PROOFVERIFY  */
    return 0;
}

/////////////////////////////////////////////////////////////////////
// FUNCTION DECLARATIONS ////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

// print to console the keychain variables
void key_printer(struct Keychain keys) {
    printf("ID: %u", keys.ID);
    printf("PK: %u", keys.pk);
    printf("SK: %u", keys.sk);
    
    return;
}

// initialize the keychain with computed values
struct Keychain init_keys() {
    struct Keychain keys;
    keys.sk = (unsigned int) (rand() % (max_number + 1 - minimum_number) + minimum_number)%MOD;
    keys.pk = (unsigned int) pow((double) G, (double) keys.sk);
    keys.ID = ID_COUNTER++;
    
    key_printer(keys);
    return keys;
}




/* RESOURCES
 *
 *  https://math.stackexchange.com/questions/814879/find-a-generator-of-the-multiplicative-group-of-mathbbz-23-mathbbz-as-a-c
 *  https://stackoverflow.com/questions/23360728/how-to-generate-a-number-of-n-bit-in-length
 *  https://stackoverflow.com/questions/2844/how-do-you-format-an-unsigned-long-long-int-using-printf
 */