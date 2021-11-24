#include <paillier.h>


/*  SOURCE:
 *  https://www.researchgate.net/publication/308277139_Paillier%27s_encryption_Implementation_and_cloud_applications  
 *  https://github.com/mikeivanov/paillier    
 */

const unsigned int smallprimes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
    47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97};
const unsigned int length = 24;

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
        /*
            else {
                printf("%lld is not an inverse for %lld mod %lld\n", d, a, p);
            }
        */
    }
    return d;
}

struct paillierKeyring generate_keypair() {
    struct paillierKeyring keyring;
    keyring.pk.n = 0;
    unsigned long long p = 0;
    unsigned long long q = 0;
    while (log2l(keyring.pk.n) < 8) {
        p = smallprimes[rand() % length];
        q = smallprimes[(rand() % length) + 1];
        keyring.pk.n = p * q;
    }
    keyring.pk.n_sq = keyring.pk.n * keyring.pk.n;
    keyring.pk.g = keyring.pk.n + 1;

    keyring.sk.l = ((p-1) * (q-1)) / gcd((p-1), (q-1));
    keyring.sk.m = invmod(keyring.sk.l, keyring.pk.n);

    return keyring;
}

unsigned long long encrypt(struct paillierPublicKey pk, unsigned long long plain) {
    int stop = 0;
    unsigned long long r = 0;
    while (stop < MAXITER) {
        r = rand() % pk.n_sq;
        if (gcd(r, pk.n) == 1 && r > 0 && r < pk.n)
            break;
        stop ++;
    }
    if(r == 0 || stop == MAXITER)
        return 0;
    
    unsigned long long cipher = (unsigned long long) (modpow(pk.g, plain, pk.n_sq) * modpow(r, pk.n, pk.n_sq)) % pk.n_sq;
    return cipher;
}

unsigned long long decrypt(struct paillierKeyring keyring, unsigned long long cipher) {
    unsigned long long x = (unsigned long long) (modpow(cipher, keyring.sk.l, keyring.pk.n_sq) % keyring.pk.n_sq - 1);
    unsigned long long plain = ((unsigned long long) roundl((long double) (x / keyring.pk.n)) * keyring.sk.m) % keyring.pk.n;
    return plain;
}

unsigned long long modpow(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    if (exp == 0)
        return 1;
    if (exp == 1)
        return base % mod;
    
    unsigned long long c = 1;
    unsigned long long e_prime = 1;
    for (e_prime; e_prime <= exp; e_prime++) {
        c = (c * base) % mod;
    }
    return c;
}

unsigned long long gcd(unsigned long long a, unsigned long long b) {
    unsigned long long c = 0;
    while (a != 0) {
        c = a;
        a = b%a;
        b = c;
    }
    return b;
}

unsigned long long add(struct paillierPublicKey pk, unsigned long long a, unsigned long long b) {
    //Add one encrypted unsigned long longeger to another
    return (a * b) % pk.n_sq;
}

unsigned long long add_const(struct paillierPublicKey pk, unsigned long long a, unsigned long long n) {
    //Add constant n to an encrypted unsigned long longeger
    return (a * modpow(pk.g, n, pk.n_sq)) % pk.n_sq;
}

unsigned long long mul_const(struct paillierPublicKey pk, unsigned long long a, unsigned long long n) {
    //Multiplies an encrypted unsigned long longeger by a constant
    return modpow(a, n, pk.n_sq);
}