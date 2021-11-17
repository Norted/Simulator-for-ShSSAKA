#include <stdio.h>
#include <math.h>
// extern headers
#include "paillier.h"
#include "primes.h"


/*  SOURCE:
 *  https://www.researchgate.net/publication/308277139_Paillier%27s_encryption_Implementation_and_cloud_applications  
 *  https://github.com/mikeivanov/paillier    
 */


unsigned long long invmod(unsigned long long a, unsigned long long p) {
    /*
     *  Multiplicitive inverse of a in Z_p:
     *  a * b == 1 mod p
     *  (http://code.activestate.com/recipes/576737-inverse-modulo-p/)
     */
    
    if (a == 0) {
        printf("0 has no inverse mod %lld\n", p);
    }
    unsigned long long r = a;
    unsigned long long d = 1;
    unsigned int max = 0;
    if(p < 1000000)
        max = p;
    else
        max = 1000000;
    for (unsigned int i = 0; i <= max; i++) {
        d = ((unsigned long long) (floor(p / r) + 1) * d) % p;
        r = (d * a) % p;
        if (r == 1) {
            break;
        }
        else {
            printf("%lld is not an inverse for %lld mod %lld\n", d, a, p);
        }
    }
    return d;
}

unsigned long long modpow(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    while (exp > 0) {
        if ((exp & 1) == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

struct paillierKeyring generate_keypair(int bits) {
    struct paillierKeyring keyring;
    if (bits < 16) {
        printf("Size of the bits value must be bigger or equal 16!\n");
        return keyring;
    }

    keyring.pk.n = 0;
    unsigned long long p = 0;
    unsigned long long q = 0;
    while (log2l(keyring.pk.n) < 8) {
        p = generate_prime((unsigned long long) (bits / 2));
        q = generate_prime((unsigned long long) (bits / 2));
        keyring.pk.n = p * q;
    }
    keyring.pk.n_sq = keyring.pk.n * keyring.pk.n;
    keyring.pk.g = keyring.pk.n + 1;

    keyring.sk.l = (p-1) * (q-1);
    keyring.sk.m = invmod(keyring.sk.l, keyring.pk.n);

    return keyring;
}

unsigned long long encrypt(struct paillierPublicKey pk, unsigned long long plain) {
    int stop = 0;
    unsigned long long r = 0;
    while (stop < 100) {
        r = generate_prime((unsigned long long) roundl(log2l((long double) pk.n)));
        if (r > 0 && r < pk.n)
            break;
        stop ++;
    }
    if(r == 0)
        return 0;
    
    unsigned long long x = (unsigned long long) _binpow(r, pk.n, pk.n_sq);
    unsigned long long cipher = (unsigned long long) (_binpow(pk.g, plain, pk.n_sq) * x) % pk.n_sq;
    return cipher;
}

unsigned long long decrypt(struct paillierKeyring keyring, unsigned long long cipher) {
    unsigned long long x = (unsigned long long) _binpow(cipher, keyring.sk.l, keyring.pk.n_sq) - 1;
    unsigned long long plain = ((unsigned long long) floorl((long double) (x / keyring.pk.n)) * keyring.sk.m) % keyring.pk.n;
    return plain;
}


// functions to test homomorphic ability
unsigned long long e_add(struct paillierPublicKey pk, unsigned long long a, unsigned long long b) {
    //Add one encrypted unsigned long longeger to another
    return a * b % pk.n_sq;
}

unsigned long long e_const(struct paillierPublicKey pk, unsigned long long a, unsigned long long n, unsigned char operation) {
    if(operation == 'a') {
        //Add constant n to an encrypted unsigned long longeger
        return a * modpow(pk.g, n, pk.n_sq) % pk.n_sq;
    }
    else if (operation == 'm')
    {
        //Multiplies an ancrypted unsigned long longeger by a constant
        return modpow(a, n, pk.n_sq);
    }
    else {
        printf("Character %c does not stand for any operation!\n", operation);
        return 0;
    }
}