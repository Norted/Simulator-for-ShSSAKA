#include <paillier.h>


/*  SOURCE:
 *  https://www.researchgate.net/publication/308277139_Paillier%27s_encryption_Implementation_and_cloud_applications  
 *  https://github.com/mikeivanov/paillier    
 */

unsigned int generate_keypair(struct paillierKeychain *keyring) {
    unsigned char p[BUFFER];
    unsigned char q[BUFFER];
    unsigned int err = 0;

    err += bn_genPrime(p, BITS);
    err += bn_genPrime(q, BITS);
    err += bn_mul(p, q, keyring->pk.n);
    
    err += bn_exp(keyring->pk.n, "2", keyring->pk.n_sq);
    random_str_num_in_range(keyring->pk.g, keyring->pk.n_sq, 1);

    err += bn_lcm(p, q, keyring->sk.l);
    unsigned char p_1[BUFFER];
    err += bn_modexp(keyring->pk.g, keyring->sk.l, keyring->pk.n_sq, p_1);
    unsigned char p_2[BUFFER];
    err += bn_sub(p_1, "1", p_2);
    unsigned char p_3[BUFFER];
    unsigned char rem[BUFFER];
    err += bn_div(p_2, keyring->pk.n, p_3, rem);
    err += bn_modinverse(p_3, keyring->pk.n, keyring->sk.m);

    if(err != 9)
        return 0;

    return 1;
}

unsigned int encrypt(struct paillierPublicKey pk, unsigned char *plain, unsigned char *cipher) {
    if(bn_cmp(plain, pk.n) != -1)
        return 0;
    
    int stop = 0;
    unsigned int err = 0;
    unsigned char r[BUFFER];
    unsigned char *rnd = malloc(sizeof(int));
    unsigned char gcd[sizeof(int)];
    
    while (stop < MAXITER) {
        random_str_num(rnd);
        bn_mod(rnd, pk.n, r);
        bn_gcd(r, pk.n, gcd);
        if (bn_cmp(gcd, "1") == 0 && bn_cmp(r, "0") == 1 && bn_cmp(r, pk.n) == -1)
            break;
        stop ++;
    }
    err += 2;
    free(rnd);
    
    if(bn_cmp(r, "0") == 0 || stop == MAXITER) {
        return 0;
    }

    unsigned char c_1[BUFFER];
    err += bn_modexp(pk.g, plain, pk.n_sq, c_1);
    unsigned char c_2[BUFFER];
    err += bn_modexp(r, pk.n, pk.n_sq, c_2);
    err += bn_modmul(c_1, c_2, pk.n_sq, cipher);

    if(err != 5)
        return 0;
    
    return 1;
}

unsigned int decrypt(struct paillierKeychain *keyring, unsigned char *cipher, unsigned char *plain) {
    unsigned int err = 0;
    unsigned char p_1[BUFFER];
    err += bn_modexp(cipher, keyring->sk.l, keyring->pk.n_sq, p_1);
    unsigned char p_2[BUFFER];
    err += bn_sub(p_1, "1", p_2);
    unsigned char p_3[BUFFER];
    unsigned char rem[BUFFER];
    err += bn_div(p_2, keyring->pk.n, p_3, rem);
    err += bn_modmul(p_3, keyring->sk.m, keyring->pk.n, plain);

    if(err != 4)
        return 0;
    
    return 1;
}

unsigned int add(struct paillierPublicKey pk, unsigned char *a, unsigned char *b, unsigned char *res) {
    //Add one encrypted unsigned long longeger to another
    unsigned int err = bn_modmul(a, b, pk.n_sq, res);
    return err;
}

unsigned int add_const(struct paillierPublicKey pk, unsigned char *a, unsigned char *n, unsigned char *res) {
    //Add constant n to an encrypted unsigned long longeger
    unsigned int err = 0;
    unsigned char p_1[BUFFER];
    err += bn_modexp(pk.g, n, pk.n_sq, p_1);
    err += bn_modmul(a, p_1, pk.n_sq, res);

    if(err != 2)
        return 0;
    
    return 1;
}

unsigned int mul_const(struct paillierPublicKey pk, unsigned char *a, unsigned char *n, unsigned char *res) {
    //Multiplies an encrypted unsigned long longeger by a constant
    unsigned int err = bn_modexp(a, n, pk.n_sq, res);
    return err;
}