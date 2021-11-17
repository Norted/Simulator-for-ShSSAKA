#include <stdio.h>
#include <stdlib.h>
#include <math.h>
// local headers
#include <primes.h>

/*  SOURCE:
 *  https://www.researchgate.net/publication/308277139_Paillier%27s_encryption_Implementation_and_cloud_applications  
 *  https://github.com/mikeivanov/paillier    
 */

// definition of global value smallprimes
const unsigned long long smallprimes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97};

void ipow(unsigned long long * values, unsigned long long a, unsigned long long b, unsigned long long n) {
    //  (a**b) % n via binary exponentiation
    unsigned long long A = a = a % n;
    values[0] = A;
    unsigned long long t = 1LLU;
    while (t <= b)
        t <<= 1;

    // t = 2^k, and t > b
    t >>= 2;
    
    unsigned long long i = 1;
    while (t) {
        A = (A * A) % n;
        if (t & b)
            A = (A * a) % n;
        values[i++] = A;
        t >>= 1;
    }
}

int rabin_miller_witness(unsigned long long test, unsigned long long possible, int bits) {
    unsigned long long values[bits];
    ipow(values, test, possible-1, possible);
    for (unsigned long long i = 0; i < bits; i++) {
        if (values[i] == 1)
            return 0; // may be prime
    }
    return 1; // NOT be prime
}

unsigned long long default_k(int bits) {
    return fmax(40, 2 * bits);
}

int is_probably_prime(unsigned long long possible, int bits) { // k=None
    if (possible == 1)
        return 1;
    unsigned long long k = default_k(sizeof(possible));
    for (unsigned long long i = 0; i < (unsigned long long) (sizeof(smallprimes) / sizeof(smallprimes[0])); i++) {
        if (possible == smallprimes[i])
            return 1;
        if (possible % smallprimes[i] == 0)
            return 0;
    }
    for (unsigned long long i = 0; i <= k; i++) { // % (g_maxRandomNumber + 1 - g_minRandomNumber) + g_minRandomNumber)
        unsigned long long test = (unsigned long long) random() % possible | 1;
        if (rabin_miller_witness(test, possible, bits) == 1)
            return 0;
    }
    return 1;
}

unsigned long long generate_prime(int bits) {
    if (bits < 8){
        printf("Size of the bits value must be bigger or equal 8!\n");
        return 0;
    }

    unsigned long long k = default_k(bits);

    unsigned long long stop = 0;
    unsigned long long possible = 0;
    while (stop == 0) {
        possible = (unsigned long long) (random() % (unsigned long long) (((_binpow(2, bits, 100007) + 1) - _binpow(2, bits-1, 100007) + 1) + _binpow(2, (bits-1) + 1, 100007))) | 1;
        if (is_probably_prime(possible, bits) == 1) {
            stop = 1;
        } 
    }
    return possible;
}

/*  BINAR POWER MOD FUNCTION    */
unsigned long long _binpow(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    base %= mod;
    unsigned long long res = 1;
    while (exp > 0) {
        if (exp & 1)
            res = res * base % mod;
        base = base * base % mod;
        exp >>= 1;
    }
    return res;
}