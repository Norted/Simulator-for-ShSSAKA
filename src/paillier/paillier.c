#include <stdio.h>
#include <math.h>
#include "paillier.h"
#include "primes.h"

/*  https://www.researchgate.net/publication/308277139_Paillier%27s_encryption_Implementation_and_cloud_applications  
 *  https://github.com/mikeivanov/paillier    
 */

unsigned long long invmod(unsigned long long a, unsigned long long p) {
    if (a == 0) {
        printf('0 has no inverse mod %d\n', p);
    }
    unsigned long long r = a;
    unsigned long long d = 1;
    for (unsigned long long i = p; i <= 1000000; i++) {
        d = ((unsigned long long) (floor(p / r) + 1) * d) % p;
        r = (d * a) % p;
        if (r == 1) {
            break;
        }
        else {
            printf("%llu has no inverse mod %llu\n", a, p);
        }
    }
    return d;
}

unsigned long long modpow(unsigned long long base, unsigned long long exponent, unsigned long long modulus) {
    unsigned long long result = 1;
    while (exponent > 0) {
        if (exponent & 1 == 1)
            result = (result * base) % modulus;
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    return result;
}

struct paillierKeyring generate_keypair(unsigned long long bits) {
    struct paillierKeyring keyring;
    unsigned long long p = generate_prime(bits / 2, NULL);
    unsigned long long q = generate_prime(bits / 2, NULL);
    keyring.pk.n = p * q;
    keyring.pk.n_sq = keyring.pk.n * keyring.pk.n;
    keyring.pk.g = keyring.pk.n + 1;

    keyring.sk.l = (p-1) * (q-1);
    keyring.sk.m = invmod(keyring.sk.l, keyring.pk.n);

    return keyring;
}

unsigned long long encrypt(struct paillierPublicKey pk, unsigned long long plain) {
    int stop = 0;
    unsigned long long r;
    while (stop < 1000) {
        unsigned long long r = generate_prime((unsigned long long) round(log(pk.n)/log(2)), NULL);
        if (r > 0 && r < pk.n)
            break;
        stop ++;
    }
    unsigned long long x = (unsigned long long) pow(r, pk.n) % pk.n_sq;
    unsigned long long cipher = (((unsigned long long) pow(pk.g, plain) % pk.n_sq) * x) % pk.n_sq;
    return cipher;
}

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
        return -1;
    }
}

unsigned long long decrypt(struct paillierKeyring keyring, unsigned long long cipher) {
    unsigned long long x = ((unsigned long long) pow(cipher, keyring.sk.l) % keyring.pk.n_sq) - 1;
    unsigned long long plain = ((unsigned long long) floor(x / keyring.pk.n) * keyring.sk.m) % keyring.pk.n;
    return plain;
}