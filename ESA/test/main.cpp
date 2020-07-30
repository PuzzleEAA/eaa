//
//  main.c
//  FMSketch
//
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <iostream>
#include <string.h>

using namespace std;



int main(int argc, const char * argv[])
{
    EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* g = EC_POINT_dup(EC_GROUP_get0_generator(curve),curve);
    BIGNUM* order = BN_new();;
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP_get_order(curve, order, ctx);
    
    
    BIGNUM *r = BN_new();
    EC_POINT *point = EC_POINT_new(curve);
    EC_POINT_mul(curve, point, NULL, g, r, ctx);
    EC_POINT *point_inv = EC_POINT_dup(point, curve);
    EC_POINT_invert(curve, point_inv, ctx);
    EC_POINT_add(curve, point, point_inv, point, ctx);
    if (EC_POINT_is_at_infinity(curve, point))
        cout << "ok" << endl;
    else
        cout << "wrong" << endl;
}

