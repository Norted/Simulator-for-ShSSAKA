#include <globals.h>

struct globals g_globals;

void init_g_global() {
    //unsigned int generators[] = {2, 3, 10, 13, 14, 15};
    //sprintf(g_globals.g_q, "%d", 19);
    //sprintf(g_globals.g_g, "%d", 2); //"%u", generators[rand() % G_GENERATORSLEN]);

    unsigned int err = 0;
    unsigned char g[BUFFER];
    unsigned char p[BUFFER];
    unsigned char q[BUFFER];
    
    err = bn_genparams(p, q, g);
    //err += schnorr_group(g, q);

    //strcpy(g_globals.g_q, q);
    //strcpy(g_globals.g_g, g);
    g_globals.g_idCounter = 1;

    return;
}

unsigned int schnorr_group(unsigned char *g, unsigned char *p) {
    unsigned int err = 0;
    unsigned int stop = 0;
    unsigned int counter = 0;
    unsigned char q[BUFFER];
    unsigned char r[BUFFER];
    unsigned char i_str[BUFFER];
    unsigned char rem[BUFFER];
    unsigned char p_sub[BUFFER];
    unsigned char *one = "1";
    strcat(i_str, one);

    while(stop == 0 || counter <= 10) {
        err += bn_genPrime(p, BITS);
        err += bn_genPrime(q, BITS);
        err += bn_sub(p, one, p_sub);
        err += bn_div(p_sub, q, r, rem);
        for (int i = 2; bn_cmp(i_str, p_sub) == -1; i++) {
            sprintf(i_str, "%d", i);
            err += bn_modexp(i_str, r, p, g);
            if(bn_cmp(g, one) != 0) {
                stop = 1;
                counter = 11;
                break;
            }
            err--;
        }
        err = 0;
        counter++;
    }
    return 1;
}