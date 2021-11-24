#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <paramgen.h>

unsigned int g_upper = 20;
unsigned int g_lower = 3;

unsigned int genPrime() {
    unsigned int n = 0;
    unsigned int i = 0;
    unsigned int counter = 0;
    unsigned int flag = 0;

    while (counter < 1000){
        n = random() % (g_upper - g_lower + 1) + g_lower;
        for (i = 2; i <= n/2; ++i) { //roundl((long double) sqrtl(n))
            if (n % i == 0) {
                flag = 1;
                break;
            }
        }

        if (n == 1) {
            printf("1 is neither prime nor composite.\n");
        } 
        else {
            if (flag == 0)
                return n; // is a prime number
            else
                printf("%u is not a prime number.\n", n);
        }
        counter ++;
        flag = 0;
    }

    printf("No prime was generated. Operation took too long!\n");
    return 0;
}

int genGenerators(unsigned int q, unsigned int *arr) {
    int i = 0;
    int counter = 1;
    while (counter <= (q - 1)) {
        unsigned int tmp_arr[BUFFER];
        for (int j = 0; j < 100; j++) {
            unsigned int tmp = modular_pow(counter, j, q);
            if (valueInArray(tmp, j, tmp_arr) == 1) {
                arr[i] = counter;
                i++;
                counter++;
                break;
            }
            else
                tmp_arr[j] = tmp;
        }
    }
    return i;
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

unsigned int modular_pow(unsigned int base, unsigned int exponent, unsigned int modulus) {
    if (modulus == 1)
        return 0;
    if (exponent == 0)
        return 1;
    if (exponent == 1)
        return base % modulus;
    
    unsigned int c = 1;
    unsigned int e_prime = 0;
    for (e_prime; e_prime < exponent-1; e_prime++)
        c = (c * base) % modulus;
    return c;
}
