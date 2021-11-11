#include <random.h>
#include <stdio.h>
#include "primes.h"

/*  https://www.researchgate.net/publication/308277139_Paillier%27s_encryption_Implementation_and_cloud_applications  
 *  https://github.com/mikeivanov/paillier    
 */

int ipow(int a, int b, int n) {
    // calculates (a**b) % n via binary exponentiation, yielding itermediate results as Rabin-Miller requires
    int A = a = (int) a % n;
    //TODO:
    // yield A   →→→ ???
    int t = 1L;
    while (t <= b)
        t <<= 1;

    // t = 2**k, and t > b
    t >>= 2;
    
    while (t) {
        A = (A * A) % n;
        if (t & b)
            A = (A * a) % n;
        //TODO:
        // yield A   →→→ ???
        t >>= 1;
    }
}

int rabin_miller_witness(test, possible) {
    /*  Using Rabin-Miller witness test,
     *  will return True if possible is definitely not prime (composite),
     *  False if it may be prime.
     */
    return 0; ///return 1 not in ipow(test, possible-1, possible);    →→→→ ????
}

int default_k(int bits) {
    return max(40, 2 * bits);
}

int is_probably_prime(int possible, int k) { // k=None
    if (possible == 1)
        return 1;
    if (isnone(k))
        k = default_k(sizeof(possible));
    for (int i = 0; i < sizeof(smallprimes) / sizeof(smallprimes[0]); i++) {
        if (possible == i)
            return 1;
        if (possible % i == 0)
            return 0;
    }
    for (int i = 0; i <= k; i++) {
        int test = random() % (possible - 2) + 2 | 1;
        if (rabin_miller_witness(test, possible))
            return 0;
    }
    return 1;
}

int generate_prime(int bits, int k) { // k=None
    /*  Will generate an integer of b bits that is probably prime 
     *  (after k trials). Reasonably fast on current hardware for 
     *  values of up to around 512 bits.
     */
    
    if (bits < 8){
        printf("Size of the bits value must be bigger or equal 8!\n");
        return -1;
    }

    if (isnone(k)) {
        k = default_k(bits);
    }

    int stop = 0;
    int possible;
    while (stop == 0) {
        possible = random() % (pow(2, bits) + 1 - (pow(2, bits-1) + 1)) +  (pow(2, bits-1) + 1) | 1;
        if (is_probably_prime(possible, k)) {
            stop = 1;
        }
            
    }
    return possible;
}