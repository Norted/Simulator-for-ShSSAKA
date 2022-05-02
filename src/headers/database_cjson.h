#ifndef __DATABASE_CJSON_H__
#define __DATABASE_CJSON_H__

#include <globals.h>
#include <database_cjson.h>

int precomputation(const char *restrict file_name, struct paillierKeychain *keychain, unsigned int range, unsigned int type);
cJSON *message_precomp(unsigned int range, unsigned char *base, unsigned char *mod);
cJSON *noise_precomp(unsigned int range, unsigned char *exp_value, unsigned char *mod);
cJSON *parse_JSON(const char *restrict file_name);
unsigned int find_value(cJSON *json, unsigned char *search, unsigned char *result);
int save_keys(const char *restrict file_name, struct paillierKeychain *keychain);
void read_keys(const char *restrict file_name, struct paillierKeychain *keychain);

#endif