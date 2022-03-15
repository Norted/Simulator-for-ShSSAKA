#include <support_functions.h>

unsigned int gen_pqg_params(BIGNUM *p, BIGNUM *q, BIGNUM *lambda, struct paillier_PublicKey *pk)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    BIGNUM *p_sub = BN_new();
    BIGNUM *q_sub = BN_new();
    BIGNUM *pq_sub = BN_new();
    BIGNUM *tmp_gcd = BN_new();
    unsigned int i = 0;

    for (i; i < MAXITER; i++)
    {
        err += BN_generate_prime_ex2(p, BITS, 1, NULL, NULL, NULL, ctx);
        err += BN_generate_prime_ex2(q, BITS, 1, NULL, NULL, NULL, ctx);
        err += BN_mul(pk->n, p, q, ctx);

        err += BN_sub(p_sub, p, BN_value_one());
        err += BN_sub(q_sub, q, BN_value_one());
        err += BN_mul(pq_sub, p_sub, q_sub, ctx);

        err += BN_gcd(tmp_gcd, pk->n, pq_sub, ctx);
        if (BN_is_one(tmp_gcd) == 1)
            break;
        err -= 7;
    }

    if (i == MAXITER)
    {
        printf(" * MAXITER! P, Q not generated!\n");
        goto end;
    }

    const BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    err += BN_exp(pk->n_sq, pk->n, two, ctx);
    BN_free(two);

    err += l_or_a_computation(p, q, lambda);

    i = 0;
    BIGNUM *tmp_g = BN_new();
    BIGNUM *tmp_u = BN_new();
    for (i; i < MAXITER; i++)
    {
        err += BN_rand_range(tmp_g, pk->n_sq);
        err += BN_gcd(tmp_gcd, tmp_g, pk->n_sq, ctx);
        if (BN_is_one(tmp_gcd) != 1)
        {
            err -= 2;
            continue;
        }

        err += BN_mod_exp(tmp_u, tmp_g, lambda, pk->n_sq, ctx);
        err += L(tmp_u, pk->n, tmp_u, ctx);
        err += BN_gcd(tmp_gcd, tmp_u, pk->n, ctx);
        if (BN_is_one(tmp_gcd) == 1)
        {
            BN_copy(pk->g, tmp_g);
            break;
        }
        err -= 5;
    }

end:
    BN_free(p_sub);
    BN_free(q_sub);
    BN_free(pq_sub);
    BN_free(tmp_g);
    BN_free(tmp_gcd);
    BN_free(tmp_u);
    BN_CTX_free(ctx);

    if (i == MAXITER)
    {
        printf(" * MAXITER! G not found!\n");
        return 0;
    }

    if (err != 14)
        return 0;
    return 1;
}

unsigned int gen_DSA_params(BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    unsigned int err = 0;
    const DSA *dsa = DSA_new();
    BIGNUM *dsa_p = BN_new();
    BIGNUM *dsa_q = BN_new();
    BIGNUM *dsa_g = BN_new();

    err += DSA_generate_parameters_ex(dsa, BITS * 2, NULL, 0, NULL, NULL, NULL);
    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);

    BN_copy(p, dsa_p);
    BN_copy(q, dsa_q);
    BN_copy(g, dsa_g);

    DSA_free(dsa);

    if (err != 1)
        return 0;
    return 1;
}

unsigned int lcm(BIGNUM *a, BIGNUM *b, BIGNUM *res)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    BIGNUM *bn_mul = BN_new();
    err = BN_mul(bn_mul, a, b, ctx);
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *bn_gcd = BN_new();
    err = BN_gcd(bn_gcd, a, b, ctx);
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *bn_rem = BN_new();
    err = BN_div(res, bn_rem, bn_mul, bn_gcd, ctx);

end:
    BN_free(bn_mul);
    BN_free(bn_gcd);
    BN_free(bn_rem);
    BN_CTX_free(ctx);

    return err;
}

unsigned int count_mi(BIGNUM *mi, BIGNUM *g, BIGNUM *lambda, BIGNUM *n_sq, BIGNUM *n)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX!\n");
        return 0;
    }

    BIGNUM *u = BN_new();

    err = BN_mod_exp(u, g, lambda, n_sq, ctx);
    if (err == 0)
    {
        goto end;
    }

    err = L(u, n, u, ctx);
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *inv = BN_new();
    BN_mod_inverse(inv, u, n, ctx);
    BN_copy(mi, inv);

end:
    BN_free(u);
    BN_free(inv);
    BN_CTX_free(ctx);

    return err;
}

unsigned int L(BIGNUM *u, BIGNUM *n, BIGNUM *res, BN_CTX *ctx)
{
    unsigned int err = 0;
    if (!ctx)
        return 0;

    err = BN_sub(u, u, BN_value_one());
    if (err == 0)
    {
        goto end;
    }

    BIGNUM *rem = BN_new();
    err = BN_div(res, rem, u, n, ctx);
    if (err == 0)
    {
        goto end;
    }

end:
    BN_free(rem);

    return err;
}

unsigned int l_or_a_computation(BIGNUM *p, BIGNUM *q, BIGNUM *lambda)
{
    unsigned int err = 0;
    BIGNUM *p_sub = BN_new();
    BIGNUM *q_sub = BN_new();
    err += BN_sub(p_sub, p, BN_value_one());
    err += BN_sub(q_sub, q, BN_value_one());
    err += lcm(p_sub, q_sub, lambda);

    BN_free(p_sub);
    BN_free(q_sub);

    if (err != 3)
        return 0;
    return 1;
}

unsigned int generate_rnd(BIGNUM *range, BIGNUM *gcd_chck, BIGNUM *random, unsigned int strength)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        printf(" * Failed to generate CTX!\n");
        return 0;
    }

    BIGNUM *tmp_gcd = BN_new();
    int i = 0;
    for (i; i < MAXITER; i++)
    {
        err += BN_rand_range_ex(random, range, strength, ctx);
        err += BN_gcd(tmp_gcd, random, gcd_chck, ctx);
        if (BN_is_one(tmp_gcd) == 1 && BN_is_zero(random) == 0 && BN_cmp(random, range) == -1 && err == 2)
            break;
        err -= 2;
    }

    if (BN_is_zero(random) == 1 || i == MAXITER)
    {
        printf(" * RND fail\tRND: %s, I: %d\n", BN_bn2dec(random), i);
        return 0;
    }

    if (err != 2)
        return 0;
    return 1;
}

unsigned int hash(BIGNUM *res, BIGNUM *Y, BIGNUM *t_s, BIGNUM *kappa)
{
    unsigned int err = 0;
    unsigned char *inbuf = (char *) calloc(1, BUFFER * 2);
    strcat(inbuf, BN_bn2dec(Y));
    strcat(inbuf, BN_bn2dec(t_s));
    if (BN_is_zero(kappa) != 1)
        strcat(inbuf, BN_bn2dec(kappa));
    else
    {
        printf(" * KAPPA is ZERO! Hash creation failed! (support_function, hash)\n");
        goto end;
    }

    unsigned char *outbuf = (char *) malloc(SHA256_DIGEST_LENGTH);
    SHA256(inbuf, strlen(inbuf), outbuf);

    unsigned char *digest = (char *) malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    digest[SHA256_DIGEST_LENGTH * 2] = '\0';
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        snprintf(&(digest[i * 2]), SHA256_DIGEST_LENGTH, "%02x", (unsigned int)outbuf[i]);
    }
    BN_hex2bn(&res, digest);
    err = 1;

end:
    free(outbuf);
    free(inbuf);
    free(digest);
    return err;
}

unsigned int chinese_remainder_theorem(BIGNUM *num[], BIGNUM *rem[], int size, BIGNUM *result)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    BIGNUM *prod = BN_new();
    BN_dec2bn(&prod, "1");

    int i;
    for (i = 0; i < size; i++)
    {
        err = BN_mul(prod, num[i], prod, ctx);
        if (err != 1)
        {
            printf(" * Product computation failed! (support functions, chinese_remainder_theorem)\n");
            goto end;
        }
    }

    BIGNUM *tmp_inv = BN_new();
    BIGNUM *tmp_prod = BN_new();
    BIGNUM *tmp_div = BN_new();

    for (i = 0; i < size; i++)
    {
        err = BN_div(tmp_div, NULL, prod, num[i], ctx);
        if (err != 1)
        {
            printf(" * Division failed! (support functions, chinese_remainder_theorem)\n");
            goto end;
        }
        BN_mod_inverse(tmp_inv, tmp_div, num[i], ctx);
        if (BN_is_zero(tmp_inv) == 1)
        {
            printf(" * Product computation failed! (support functions, chinese_remainder_theorem)\n");
            goto end;
        }
        err = BN_mul(tmp_prod, rem[i], tmp_inv, ctx);
        if (err != 1)
        {
            printf(" * Multiplication of %d reminder and inverse failed! (support functions, chinese_remainder_theorem)\n", i);
            goto end;
        }
        err = BN_mul(tmp_prod, tmp_prod, tmp_div, ctx);
        if (err != 1)
        {
            printf(" * Multiplication of product and quotient failed! (support functions, chinese_remainder_theorem)\n");
            goto end;
        }
        err = BN_add(result, result, tmp_prod);
        if (err != 1)
        {
            printf(" * Addition to result failed! (support functions, chinese_remainder_theorem)\n");
            goto end;
        }
    }

    err = BN_nnmod(result, result, prod, ctx);
    if (err != 1)
    {
        printf(" * Modulo operation failed! (support functions, chinese_remainder_theorem)\n");
        goto end;
    }

end:
    BN_free(prod);
    BN_free(tmp_inv);
    BN_free(tmp_prod);
    BN_free(tmp_div);
    BN_CTX_free(ctx);

    return err;
}

void init_keychain(struct paillier_Keychain *keychain)
{
    keychain->pk = malloc(sizeof(struct paillier_PublicKey));
    keychain->pk->g = BN_new();
    keychain->pk->n = BN_new();
    keychain->pk->n_sq = BN_new();
    keychain->sk.lambda = BN_new();
    keychain->sk.mi = BN_new();
    keychain->sk.p = BN_new();
    keychain->sk.q = BN_new();

    return;
}

void free_keychain(struct paillier_Keychain *keychain)
{
    BN_free(keychain->pk->g);
    BN_free(keychain->pk->n);
    BN_free(keychain->pk->n_sq);
    free(keychain->pk);
    BN_free(keychain->sk.lambda);
    BN_free(keychain->sk.mi);
    BN_free(keychain->sk.p);
    BN_free(keychain->sk.q);

    return;
}

cJSON *parse_JSON(const char *restrict file_name)
{
    cJSON *json = cJSON_CreateObject();
    FILE *file = fopen(file_name, "r");
    if (file == NULL)
    {
        printf(" * Opening the file %s failed!\n", file_name);
        return NULL;
    }

    fseek(file, 0L, SEEK_END);
    long fileSize = ftell(file);
    // printf(" * File size: %lu\n", fileSize);
    fseek(file, 0, SEEK_SET);

    char *jsonStr = (char *)malloc(sizeof(char) * fileSize + 1); // Allocate memory that matches the file size
    memset(jsonStr, 0, fileSize + 1);

    int size = fread(jsonStr, sizeof(char), fileSize, file); // Read json string in file
    if (size == 0)
    {
        printf(" * Failed to read the file %s!\n", file_name);
        fclose(file);
        return 0;
    }
    // printf("%s", jsonStr);

    json = cJSON_Parse(jsonStr);
    if (json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf(" * Error before: %s\n", error_ptr);
        }
    }

    /* unsigned char *str = NULL;
    str = cJSON_Print(json);
    printf("%s\n", str); */

    fclose(file);
    return json;
}

unsigned int find_value(cJSON *json, BIGNUM *search, BIGNUM *result)
{
    unsigned int err = 0;
    cJSON *values = NULL;
    cJSON *value = NULL;
    unsigned char *str = NULL;
    unsigned char *search_str = BN_bn2dec(search);
    values = cJSON_GetObjectItemCaseSensitive(json, "precomputed_values");
    cJSON_ArrayForEach(value, values)
    {
        str = cJSON_GetObjectItemCaseSensitive(value, "exp")->valuestring;
        if (strcmp(search_str, str) == 0)
        {
            BN_dec2bn(&result, cJSON_GetObjectItemCaseSensitive(value, "result")->valuestring);
            err = 1;
            break;
        }
    }
    return err;
}

int save_keys(const char *restrict file_name, struct paillier_Keychain *keychain)
{
    unsigned int err = 0;
    FILE *file = fopen(file_name, "w");

    cJSON *json = cJSON_CreateObject();
    if (json == NULL)
    {
        goto end;
    }

    cJSON *pk_values = cJSON_CreateObject();
    if (pk_values == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "n", BN_bn2dec(keychain->pk->n)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "n_sq", BN_bn2dec(keychain->pk->n_sq)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "g", BN_bn2dec(keychain->pk->g)) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(json, "pk", pk_values);

    cJSON *sk_values = cJSON_CreateObject();
    if (sk_values == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "p", BN_bn2dec(keychain->sk.p)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "q", BN_bn2dec(keychain->sk.q)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "lambda", BN_bn2dec(keychain->sk.lambda)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "mi", BN_bn2dec(keychain->sk.mi)) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(json, "sk", sk_values);

    char *output = cJSON_Print(json);
    if (output == NULL)
    {
        printf(" * Failed to print json.\n");
    }

    if (!fputs(output, file))
    {
        printf(" * Failed to write to file %s!\n", file_name);
        return 0;
    }

end:
    cJSON_Delete(json);

    return fclose(file);
}

void read_keys(const char *restrict file_name, struct paillier_Keychain *keychain)
{
    unsigned int err = 0;
    cJSON *json = cJSON_CreateObject();
    json = parse_JSON(file_name);

    cJSON *pk = NULL;
    cJSON *sk = NULL;
    cJSON *value = NULL;
    pk = cJSON_GetObjectItemCaseSensitive(json, "pk");
    sk = cJSON_GetObjectItemCaseSensitive(json, "sk");

    BN_dec2bn(&keychain->pk->g, cJSON_GetObjectItemCaseSensitive(pk, "g")->valuestring);
    BN_dec2bn(&keychain->pk->n, cJSON_GetObjectItemCaseSensitive(pk, "n")->valuestring);
    BN_dec2bn(&keychain->pk->n_sq, cJSON_GetObjectItemCaseSensitive(pk, "n_sq")->valuestring);

    BN_dec2bn(&keychain->sk.lambda, cJSON_GetObjectItemCaseSensitive(sk, "lambda")->valuestring);
    BN_dec2bn(&keychain->sk.mi, cJSON_GetObjectItemCaseSensitive(sk, "mi")->valuestring);
    BN_dec2bn(&keychain->sk.p, cJSON_GetObjectItemCaseSensitive(sk, "p")->valuestring);
    BN_dec2bn(&keychain->sk.q, cJSON_GetObjectItemCaseSensitive(sk, "q")->valuestring);

    cJSON_free(json);
    return;
}

int precomputation(const char *restrict file_name, struct paillier_Keychain *keychain, unsigned int range, unsigned int type)
{ // type 1 ... message, 2 ... noise
    if (type == 1)
    {
        printf(" * Message precomputation STARTED ... \n");
    }
    else if (type == 2)
    {
        printf(" * Noise scheme 1 precomputation STARTED ... \n");
    }
    else if (type == 3)
    {
        printf(" * Noise scheme 3 precomputation STARTED ... \n");
    }
    else
    {
        printf(" * Unknown precomputation type ... (%d)\n", type);
        return 1;
    }

    unsigned int err = 0;
    FILE *file = fopen(file_name, "w");

    cJSON *json = cJSON_CreateObject();
    if (json == NULL)
    {
        goto end;
    }

    cJSON *pk_values = cJSON_CreateObject();
    if (pk_values == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "n", BN_bn2dec(keychain->pk->n)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "n_sq", BN_bn2dec(keychain->pk->n_sq)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "g", BN_bn2dec(keychain->pk->g)) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(json, "pk", pk_values);

    cJSON *sk_values = cJSON_CreateObject();
    if (sk_values == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "p", BN_bn2dec(keychain->sk.p)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "q", BN_bn2dec(keychain->sk.q)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "lambda", BN_bn2dec(keychain->sk.lambda)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "mi", BN_bn2dec(keychain->sk.mi)) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(json, "sk", sk_values);

    cJSON *precomp = cJSON_CreateArray();
    if (type == 1)
    {
        precomp = message_precomp(range, keychain->pk->g, keychain->pk->n_sq);
    }
    else
    {
        precomp = noise_precomp(range, keychain->pk->n, keychain->pk->n_sq);
    }

    cJSON_AddItemToObject(json, "precomputed_values", precomp);

    if (type == 1)
    {
        printf(" * Message precomputation DONE!\n");
    }
    else if (type == 2)
    {
        printf(" * Noise scheme 1 precomputation DONE!\n");
    }
    else
    {
        printf(" * Noise scheme 3 precomputation DONE!\n");
    }

    char *output = cJSON_Print(json);
    if (output == NULL)
    {
        printf(" * Failed to print json.\n");
    }

    if (!fputs(output, file))
    {
        printf(" * Failed to write to file %s!\n", file_name);
        return 0;
    }

end:
    cJSON_Delete(json);

    return fclose(file);
}

cJSON *message_precomp(BIGNUM *range, BIGNUM *base, BIGNUM *mod)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        goto end;
    }
    BIGNUM *tmp_value = BN_new();
    BIGNUM *tmp_result = BN_new();

    cJSON *precomp = cJSON_CreateArray();
    if (precomp == NULL)
    {
        goto end;
    }

    cJSON *values = NULL;
    unsigned char string[BUFFER];
    for (int i = 1; i < range; i++)
    {
        sprintf(string, "%d", i);
        BN_dec2bn(&tmp_value, string);
        if (!BN_mod_exp(tmp_result, base, tmp_value, mod, ctx))
        {
            printf(" * Precomputation STOPPED at %s!\n", BN_bn2dec(tmp_value));
            return -1;
        }

        values = cJSON_CreateObject();
        if (values == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "exp", string) == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "result", BN_bn2dec(tmp_result)) == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(precomp, values);
    }

end:
    BN_free(tmp_value);
    BN_free(tmp_result);
    BN_CTX_free(ctx);

    return precomp;
}

cJSON *noise_precomp(BIGNUM *range, BIGNUM *exp_value, BIGNUM *mod)
{
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        goto end;
    }
    BIGNUM *tmp_value = BN_new();
    BIGNUM *tmp_result = BN_new();

    cJSON *precomp = cJSON_CreateArray();
    if (precomp == NULL)
    {
        goto end;
    }

    cJSON *values = NULL;
    unsigned char string[BUFFER];
    for (int i = 1; i < range; i++)
    {
        sprintf(string, "%d", i);
        BN_dec2bn(&tmp_value, string);
        if (!BN_mod_exp(tmp_result, tmp_value, exp_value, mod, ctx))
        {
            printf(" * Precomputation STOPPED at %s!\n", BN_bn2dec(tmp_value));
            return -1;
        }

        values = cJSON_CreateObject();
        if (values == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "exp", string) == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "result", BN_bn2dec(tmp_result)) == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(precomp, values);
    }

end:
    BN_free(tmp_value);
    BN_free(tmp_result);
    BN_CTX_free(ctx);

    return precomp;
}