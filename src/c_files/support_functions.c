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
    BIGNUM *two = BN_new();
    BN_dec2bn(&two, "2");
    BIGNUM *tmp_g = BN_new();
    BIGNUM *tmp_u = BN_new();
    unsigned int i = 0;

    for (i; i < MAXITER; i++)
    {
        err = BN_generate_prime_ex2(p, BITS, 1, NULL, NULL, NULL, ctx);
        if (err != 1)
        {
            printf(" * Gereation of a P prime failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        err = BN_generate_prime_ex2(q, BITS, 1, NULL, NULL, NULL, ctx);
        if (err != 1)
        {
            printf(" * Gereation of a Q prime failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        err = BN_mul(pk->n, p, q, ctx);
        if (err != 1)
        {
            printf(" * Computation of N failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }

        err = BN_sub(p_sub, p, BN_value_one());
        if (err != 1)
        {
            printf(" * Substraction of P failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        err = BN_sub(q_sub, q, BN_value_one());
        if (err != 1)
        {
            printf(" * Substraction of Q failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        err = BN_mul(pq_sub, p_sub, q_sub, ctx);
        if (err != 1)
        {
            printf(" * Multiplication of P_SUB and Q_SUB failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }

        err = BN_gcd(tmp_gcd, pk->n, pq_sub, ctx);
        if (err != 1)
        {
            printf(" * Computation of GCD(N, PQ_SUB) failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }

        if (BN_is_one(tmp_gcd) == 1)
            break;
    }

    if (i == MAXITER)
    {
        printf(" * MAXITER! P, Q not generated!\n");
        goto end;
    }

    err = BN_exp(pk->n_sq, pk->n, two, ctx);
    if (err != 1)
    {
        printf(" * Computation of N^2 failed! (gen_pqg_params, support_functions)\n");
        goto end;
    }
    err = l_or_a_computation(p, q, lambda);
    if (err != 1)
    {
        printf(" * Computation of LAMBDA failed! (gen_pqg_params, support_functions)\n");
        goto end;
    }

    i = 0;
    for (i; i < MAXITER; i++)
    {
        err = rand_range(tmp_g, pk->n_sq);
        if (err != 1)
        {
            printf(" * Generation of random G failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        err = BN_gcd(tmp_gcd, tmp_g, pk->n_sq, ctx);
        if (err != 1)
        {
            printf(" * Computation of GCD(G, N^2) failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        if (BN_is_one(tmp_gcd) != 1)
        {
            continue;
        }

        err = BN_mod_exp(tmp_u, tmp_g, lambda, pk->n_sq, ctx);
        if (err != 1)
        {
            printf(" * Computation of U failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        err = L(tmp_u, pk->n, tmp_u, ctx);
        if (err != 1)
        {
            printf(" * Computation of L(U) failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        err = BN_gcd(tmp_gcd, tmp_u, pk->n, ctx);
        if (err != 1)
        {
            printf(" * Computation of GCD(U, N) failed! (gen_pqg_params, support_functions)\n");
            goto end;
        }
        if (BN_is_one(tmp_gcd) == 1)
        {
            BN_copy(pk->g, tmp_g);
            break;
        }
    }

end:
    BN_free(p_sub);
    BN_free(q_sub);
    BN_free(pq_sub);
    BN_free(tmp_g);
    BN_free(tmp_gcd);
    BN_free(tmp_u);
    BN_free(two);
    BN_CTX_free(ctx);

    if (i == MAXITER)
    {
        printf(" * MAXITER! G not found!\n");
        return 0;
    }

    return err;
}

unsigned int lcm(BIGNUM *a, BIGNUM *b, BIGNUM *res)
{
    unsigned int err = 0;
    BIGNUM *bn_mul = BN_new();
    BIGNUM *bn_gcd = BN_new();
    BIGNUM *bn_rem = BN_new();
    BN_CTX *ctx = BN_CTX_secure_new();
    if (!ctx)
        return 0;

    err = BN_mul(bn_mul, a, b, ctx);
    if (err != 1)
    {
        printf(" * Multiplication failed! (lcm, support_functions)\n");
        goto end;
    }

    err = BN_gcd(bn_gcd, a, b, ctx);
    if (err != 1)
    {
        printf(" * GCD failed! (lcm, support_functions)\n");
        goto end;
    }

    err = BN_div(res, bn_rem, bn_mul, bn_gcd, ctx);
    if (err != 1)
    {
        printf(" * Division failed! (lcm, support_functions)\n");
    }

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
    BIGNUM *inv = BN_new();

    err = BN_mod_exp(u, g, lambda, n_sq, ctx);
    if (err != 1)
    {
        printf(" * Exponentation failed! (count_mi, support_functions)\n");
        goto end;
    }

    err = L(u, n, u, ctx);
    if (err != 1)
    {
        printf(" * Computation of L(U) failed! (count_mi, support_functions)\n");
        goto end;
    }

    if (!BN_mod_inverse(inv, u, n, ctx))
    {
        printf(" * Computation of inverse failed! (count_mi, support_functions)\n");
        goto end;
    }

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

    BIGNUM *rem = BN_new();

    err = BN_sub(u, u, BN_value_one());
    if (err == 0)
    {
        printf(" * Substraction failed! (L, support_functions)\n");
        goto end;
    }

    err = BN_div(res, rem, u, n, ctx);
    if (err == 0)
    {
        printf(" * Division failed! (L, support_functions)\n");
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
    err = BN_sub(p_sub, p, BN_value_one());
    if (err != 1)
    {
        printf(" * Substraction failed! (l_or_a_computation, support_fuction)\n");
        goto end;
    }
    err = BN_sub(q_sub, q, BN_value_one());
    if (err != 1)
    {
        printf(" * Substraction failed! (l_or_a_computation, support_fuction)\n");
        goto end;
    }
    err = lcm(p_sub, q_sub, lambda);
    if (err != 1)
    {
        printf(" * Computation of LCM failed! (l_or_a_computation, support_fuction)\n");
        goto end;
    }

end:
    BN_free(p_sub);
    BN_free(q_sub);

    return err;
}

unsigned int generate_rnd_paillier(BIGNUM *range, BIGNUM *gcd_chck, BIGNUM *random)
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
        err = rand_range(random, range);
        if (err != 1)
        {
            printf(" * Generation of a random failed! (generate_rnd_paillier, support_functions)\n");
            goto end;
        }
        err = BN_mod(random, random, gcd_chck, ctx);
        if (err != 1)
        {
            printf(" * Modulo operation failed! (generate_rnd_paillier, support_functions)\n");
            goto end;
        }
        err = BN_gcd(tmp_gcd, random, gcd_chck, ctx);
        if (err != 1)
        {
            printf(" * GCD failed! (generate_rnd_paillier, support_functions)\n");
            goto end;
        }
        if (BN_is_one(tmp_gcd) == 1 && BN_is_zero(random) == 0)
            break;
    }

    if (BN_is_zero(random) == 1 || i == MAXITER)
    {
        printf(" * Generate good random failed (generate_rnd_paillier, support_functions)!\nRND: %s, I: %d\n", BN_bn2dec(random), i);
        goto end;
    }

end:
    BN_free(tmp_gcd);
    BN_CTX_free(ctx);

    return err;
}

unsigned int hash(BIGNUM *res, BIGNUM *Y, BIGNUM *t_s, BIGNUM *kappa)
{
    unsigned int err = 0;
    unsigned char *inbuf = (unsigned char *)calloc(BUFFER * 2, sizeof(unsigned char));
    inbuf[0] = '\0';
    for (int i = 1; i < (BUFFER * 2); i++)
        inbuf[i] = '0';
    unsigned char *outbuf = (unsigned char *)calloc(SHA256_DIGEST_LENGTH, sizeof(unsigned char));
    unsigned char *digest = (unsigned char *)calloc((SHA256_DIGEST_LENGTH * 2 + 1), sizeof(unsigned char));

    strcat(inbuf, BN_bn2dec(Y));
    strcat(inbuf, BN_bn2dec(t_s));

    if (BN_is_zero(kappa) != 1)
        strcat(inbuf, BN_bn2dec(kappa));

    SHA256(inbuf, strlen(inbuf), outbuf);

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

unsigned int ec_hash(EC_GROUP *group, BIGNUM *res, BIGNUM *Y, EC_POINT *t_s, EC_POINT *kappa)
{
    unsigned int err = 0;
    BN_CTX *ctx = BN_CTX_secure_new();
    if(!ctx)
    {
        printf(" * Failed to generate CTX! (ec_hash, support_functions)\n");
        return err;
    }

    unsigned char *inbuf = (unsigned char *)calloc(BUFFER * 2, sizeof(unsigned char));
    inbuf[0] = '\0';
    for (int i = 1; i < (BUFFER * 2); i++)
        inbuf[i] = '0';
    unsigned char *outbuf = (unsigned char *)calloc(SHA256_DIGEST_LENGTH, sizeof(unsigned char));
    unsigned char *digest = (unsigned char *)calloc((SHA256_DIGEST_LENGTH * 2 + 1), sizeof(unsigned char));

    strcat(inbuf, BN_bn2dec(Y));
    strcat(inbuf, EC_POINT_point2hex(group, t_s, POINT_CONVERSION_COMPRESSED, ctx));

    if (EC_POINT_is_at_infinity(group, kappa) != 1)
        strcat(inbuf, EC_POINT_point2hex(group, kappa, POINT_CONVERSION_COMPRESSED, ctx));

    SHA256(inbuf, strlen(inbuf), outbuf);

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

unsigned int rand_range(BIGNUM *rnd, BIGNUM *range)
{
    unsigned int err = 0;
    BIGNUM *range_sub_one = BN_new();

    err = BN_sub(range_sub_one, range, BN_value_one());
    if (err != 1)
    {
        printf(" * Substraction of one failed! (rand_range, support_functions)\n");
        goto end;
    }
    err = BN_rand_range(rnd, range_sub_one);
    if (err != 1)
    {
        printf(" * Generation of random failed! (rand_range, support_functions)\n");
        goto end;
    }

end:
    BN_free(range_sub_one);
    return err;
}

void init_serversign(EC_GROUP *group, struct ServerSign *server_sign)
{
    server_sign->tau_s = BN_new();
    server_sign->kappa = EC_POINT_new(group);
    return;
}

void free_serversign(struct ServerSign *server_sign)
{
    BN_free(server_sign->tau_s);
    EC_POINT_free(server_sign->kappa);
    return;
}

void init_clientproof(EC_GROUP *group, struct ClientProof *client_proof)
{
    client_proof->tau_c = BN_new();
    client_proof->signature = (struct schnorr_Signature *)malloc(sizeof(struct schnorr_Signature));
    init_schnorr_signature(group, client_proof->signature);
    client_proof->kappa = EC_POINT_new(group);
    return;
}

void free_clientproof(struct ClientProof *client_proof)
{
    BN_free(client_proof->tau_c);
    free_schnorr_signature(client_proof->signature);
    free(client_proof->signature);
    EC_POINT_free(client_proof->kappa);
    return;
}

void init_deviceproof(EC_GROUP *group, struct DeviceProof *device_proof)
{
    device_proof->s_i = BN_new();
    device_proof->kappa_i = EC_POINT_new(group);
    return;
}

void free_deviceproof(struct DeviceProof *device_proof)
{
    BN_free(device_proof->s_i);
    EC_POINT_free(device_proof->kappa_i);
    return;
}

void *thread_creation(void *threadid)
{ // precomputation type: 0 ... noise, 1 ... message
    unsigned int err = 0;
    long tid;
    tid = (long)threadid;

    if (tid == 0)
    {
        err = precomputation(file_precomputed_noise, &g_paiKeys, range, 0);
        if (err != 0)
        {
            printf(" * Noise precomputation failed!\n");
            pthread_exit(NULL);
        }
    }
    else if (tid == 1)
    {
        err = precomputation(file_precomputed_message, &g_paiKeys, range, 1);
        if (err != 0)
        {
            printf(" * Message precomputation failed!\n");
            pthread_exit(NULL);
        }
    }
    else
    {
        printf(" * No other thread needed! (thread no. %ld)\n", tid);
    }
    pthread_exit(NULL);
}

unsigned int threaded_precomputation()
{
    int rc;
    for (int i = 0; i < NUM_THREADS; i++)
    {
        printf("  main() : Creating thread, %d\n", i);
        rc = pthread_create(&threads[i], NULL, thread_creation, (void *)i);
        if (rc)
        {
            printf("  Error : Unable to create thread, %d\n", rc);
            exit(-1);
        }
    }

    return 0;
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

    BN_dec2bn(&keychain->sk->lambda, cJSON_GetObjectItemCaseSensitive(sk, "lambda")->valuestring);
    BN_dec2bn(&keychain->sk->mi, cJSON_GetObjectItemCaseSensitive(sk, "mi")->valuestring);
    BN_dec2bn(&keychain->sk->p, cJSON_GetObjectItemCaseSensitive(sk, "p")->valuestring);
    BN_dec2bn(&keychain->sk->q, cJSON_GetObjectItemCaseSensitive(sk, "q")->valuestring);

    cJSON_free(json);
    return;
}

int precomputation(const char *restrict file_name, struct paillier_Keychain *keychain, BIGNUM *range, unsigned int type)
{ // type 0 ... message, 1 ... noise
    if (type == 0)
    {
        printf(" * Message precomputation STARTED ... \n");
    }
    else if (type == 1)
    {
        printf(" * Noise precomputation STARTED ... \n");
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
    if (cJSON_AddStringToObject(sk_values, "p", BN_bn2dec(keychain->sk->p)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "q", BN_bn2dec(keychain->sk->q)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "lambda", BN_bn2dec(keychain->sk->lambda)) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "mi", BN_bn2dec(keychain->sk->mi)) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(json, "sk", sk_values);

    cJSON *precomp = cJSON_CreateArray();
    if (type == 0)
    {
        precomp = message_precomp(range, keychain->pk->g, keychain->pk->n_sq);
    }
    else
    {
        precomp = noise_precomp(range, keychain->pk->n, keychain->pk->n_sq);
    }

    cJSON_AddItemToObject(json, "precomputed_values", precomp);

    if (type == 0)
    {
        printf(" * Message precomputation DONE!\n");
    }
    else if (type == 1)
    {
        printf(" * Noise precomputation DONE!\n");
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
    for (int i = 0; i < atoi(BN_bn2dec(range)); i++)
    {
        sprintf(string, "%d", i);
        BN_dec2bn(&tmp_value, string);
        if (!BN_mod_exp(tmp_result, base, tmp_value, mod, ctx))
        {
            printf(" * Precomputation STOPPED at %s!\n", BN_bn2dec(tmp_value));
            precomp = NULL; //-1;
            goto end;
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
    const unsigned char string[BUFFER];
    for (int i = 1; i < atoi(BN_bn2dec(range)); i++)
    {
        sprintf((unsigned char *)string, "%d", i);
        BN_dec2bn(&tmp_value, (const char *)string);
        if (!BN_mod_exp(tmp_result, tmp_value, exp_value, mod, ctx))
        {
            printf(" * Precomputation STOPPED at %s!\n", BN_bn2dec(tmp_value));
            precomp = NULL; //-1;
            goto end;
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