#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <globals.h>
#include <paramgen.h>
#include <openssl_bn.h>

unsigned int g_upper = 20;
unsigned int g_lower = 3;

unsigned int genPrime(unsigned char *n) {
    return bn_genPrime(n, BITS);
}

unsigned int genGenerators(unsigned char *q, unsigned int *arr, unsigned char *generator) {
    int i = 0;
    unsigned int err = 0;
    unsigned char counter[BUFFER];
    strcpy(counter, "1");
    unsigned char cmp[BUFFER];

    err += bn_sub(q, "1", cmp);
    int res = bn_cmp(counter, cmp);
    while (res != -1 || res != 0) {
        unsigned int tmp_arr[BUFFER100];
        for (int j = 0; j < BUFFER100; j++) {
            unsigned char tmp[BUFFER];
            unsigned char *str_j = malloc(sizeof(unsigned char));
            sprintf(str_j, "%d", j);
            err += bn_modexp(counter, str_j, q, tmp);
            free(str_j);
            int tmp_int = atoi(tmp);
            if (valueInArray(tmp_int, j, tmp_arr) == 1) {
                err += bn_add(counter, "1", counter);
                arr[i] = atoi(counter);
                i++;
                break;
            }
            else
                tmp_arr[j] = tmp;
        }
    }
    
    sprintf(generator, "%d", i);

    if(err != 0)
        return 0;
    
    return 1;
}

int valueInArray(unsigned int val, int size ,unsigned int *arr) {
    if (size > 0) {
        for(int i = 0; i <= size; i++) {
            if(arr[i] == val)
                return 1;
        }
    }
    else
        return 0;
    return 0;
}
