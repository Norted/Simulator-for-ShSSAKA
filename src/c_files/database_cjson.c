#include <database_cjson.h>

int precomputation(const char *restrict file_name, struct paillierKeychain *keychain, unsigned int range, unsigned int type)
{ // type 0 ... message, 1 ... noise
    if (type == 0)
    {
        printf(" * Noise precomputation STARTED ... \n");
    }
    else if (type == 1)
    {
        printf(" * Message precomputation STARTED ... \n");
    }
    else
    {
        printf(" * Unknown precomputation type ... (%d)\n", type);
        return 1;
    }

    unsigned int err = 0;
    FILE *file = fopen(file_name, "w");
    if (file == NULL)
    {
        return -1;
    }

    cJSON *json = cJSON_CreateObject();
    if (json == NULL)
    {
        goto end;
    }

    cJSON *precomp = cJSON_CreateArray();
    if (type == 0)
    {
        precomp = noise_precomp(range, keychain->pk.n, keychain->pk.n_sq);
    }
    else
    {
        precomp = message_precomp(range, keychain->pk.g, keychain->pk.n_sq);
    }

    cJSON_AddItemToObject(json, "precomputed_values", precomp);

    if (type == 0)
    {
        printf(" * Message precomputation DONE!\n");
    }
    else
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

cJSON *message_precomp(unsigned int range, unsigned char *base, unsigned char *mod)
{
    unsigned int err = 0;
    unsigned char tmp_result[BUFFER];

    cJSON *precomp = cJSON_CreateArray();
    if (precomp == NULL)
    {
        goto end;
    }

    cJSON *values = NULL;
    unsigned char tmp_value[BUFFER];
    for (int i = 1; i < range; i++)
    {
        sprintf(tmp_value, "%d", i);
        err = bn_modexp(base, tmp_value, mod, tmp_result);

        values = cJSON_CreateObject();
        if (values == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "exp", tmp_value) == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "result", tmp_result) == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(precomp, values);
    }

end:
    return precomp;
}

cJSON *noise_precomp(unsigned int range, unsigned char *exp_value, unsigned char *mod)
{
    unsigned int err = 0;
    unsigned char tmp_result[BUFFER];

    cJSON *precomp = cJSON_CreateArray();
    if (precomp == NULL)
    {
        goto end;
    }

    cJSON *values = NULL;
    unsigned char tmp_value[BUFFER];
    for (int i = 1; i < range; i++)
    {
        sprintf(tmp_value, "%d", i);
        err = bn_modexp(tmp_value, exp_value, mod, tmp_result);

        values = cJSON_CreateObject();
        if (values == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "exp", tmp_value) == NULL)
        {
            goto end;
        }
        if (cJSON_AddStringToObject(values, "result", tmp_result) == NULL)
        {
            goto end;
        }

        cJSON_AddItemToArray(precomp, values);
    }

end:
    return precomp;
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

unsigned int find_value(cJSON *json, unsigned char *search, unsigned char *result)
{
    unsigned int err = 0;
    cJSON *values = NULL;
    cJSON *value = NULL;
    unsigned char *str = NULL;
    values = cJSON_GetObjectItemCaseSensitive(json, "precomputed_values");
    cJSON_ArrayForEach(value, values)
    {
        str = cJSON_GetObjectItemCaseSensitive(value, "exp")->valuestring;
        if (strcmp(search, str) == 0)
        {
            strcpy(result, cJSON_GetObjectItemCaseSensitive(value, "result")->valuestring);
            err = 1;
            break;
        }
    }
    return err;
}

int save_keys(const char *restrict file_name, struct paillierKeychain *keychain)
{
    unsigned int err = 0;
    FILE *file = fopen(file_name, "w");
    if(file==NULL)
    {
        printf(" * File %s not found!\n", file_name);
        return 0;
    }

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
    if (cJSON_AddStringToObject(pk_values, "n", keychain->pk.n) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "n_sq", keychain->pk.n_sq) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(pk_values, "g", keychain->pk.g) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(json, "pk", pk_values);

    cJSON *sk_values = cJSON_CreateObject();
    if (sk_values == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "l", keychain->sk.l) == NULL)
    {
        goto end;
    }
    if (cJSON_AddStringToObject(sk_values, "m", keychain->sk.m) == NULL)
    {
        goto end;
    }
    cJSON_AddItemToObject(json, "sk", sk_values);

    char *output = cJSON_Print(json);
    if (output == NULL)
    {
        printf("\t* Failed to print json.\n");
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

void read_keys(const char *restrict file_name, struct paillierKeychain *keychain)
{
    unsigned int err = 0;
    cJSON *json = cJSON_CreateObject();
    json = parse_JSON(file_name);

    cJSON *pk = NULL;
    cJSON *sk = NULL;
    cJSON *value = NULL;
    pk = cJSON_GetObjectItemCaseSensitive(json, "pk");
    sk = cJSON_GetObjectItemCaseSensitive(json, "sk");

    strcpy(keychain->pk.g, cJSON_GetObjectItemCaseSensitive(pk, "g")->valuestring);
    strcpy(keychain->pk.n, cJSON_GetObjectItemCaseSensitive(pk, "n")->valuestring);
    strcpy(keychain->pk.n_sq, cJSON_GetObjectItemCaseSensitive(pk, "n_sq")->valuestring);

    strcpy(keychain->sk.l, cJSON_GetObjectItemCaseSensitive(sk, "l")->valuestring);
    strcpy(keychain->sk.m, cJSON_GetObjectItemCaseSensitive(sk, "m")->valuestring);

    cJSON_free(json);
    return;
}