#include <sys/time.h>
#include <stdlib.h>

#include "ElGamal_openssl.h"
#include "benchmark_subs.h"

unsigned int loop;
unsigned int nth;
unsigned int batch;

int main(int argc, char const *argv[])
{
    if (argc != 4) {
        cout << "[!] Usage: ./benchmark.x [n_iterations] [n_threads] [n_batch for shuffle]" << endl;
        exit(-1);
    }

    loop = atoi(argv[1]);
    nth = atoi(argv[2]);
    batch = atoi(argv[3]);

    if (loop <= 0 || nth > 16 || nth <= 0 || batch <= 0) {
        cout << "[!] Invalid args!" << endl;
        exit(-1);
    }

    cout << "[*] Working with " << loop << " iterations and "
        << nth << " threads" << endl;
    cout << "[*] Set number of bins to: " << batch << endl;

    // Testbed setup: containing three parties
    ElGamal p0(3, PRINT);
    ElGamal p1(3, PRINT);
    ElGamal p2(3, PRINT);

    unsigned int counter = 0;
    BN_CTX *ctx;
    EC_GROUP *curve;
    EC_POINT *G;
    BIGNUM *q;

    struct timeval start[32], end[32];
    octetStream o[16];

    unsigned int msec;

    p0.add_other_public_key(p1.partial_public_key, 1);
    p0.add_other_public_key(p2.partial_public_key, 2);

    p1.add_other_public_key(p0.partial_public_key, 0);
    p1.add_other_public_key(p2.partial_public_key, 2);

    p2.add_other_public_key(p0.partial_public_key, 0);
    p2.add_other_public_key(p1.partial_public_key, 1);

    ctx = BN_CTX_new();
    curve = p0.curve;
    G = p0.G;
    q = p0.q;

    pthread_t *ths = new pthread_t[nth];
    workerArgs* args = new workerArgs[nth];

    cout << endl;
    cout << "---------------------- ElGamal test ----------------------" << endl;

    // Encryption benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            encryption_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " encryptions: "
        << msec << " ms" << endl;

    // Partial decryption benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            partial_decryption_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop*3 << " partial decryptions: "
        << msec << " ms" << endl;

    // Re-encryption benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            re_encryption_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " re-encryptions: "
        << msec << " ms" << endl;

    // Randomization benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            randomization_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " randomization: "
        << msec << " ms" << endl;


    cout << endl;
    cout << "-------------------- NIZK proofs test --------------------" << endl;

    // NIZK DL benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].backup_start = &(start[i + 16]);
        args[i].backup_end = &(end[i + 16]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            NIZK_DL_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_DL Prove: "
        << msec << " ms" << endl;
    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i + 16].tv_sec - start[i + 16].tv_sec)*1000 + 
            (end[i + 16].tv_usec - start[i + 16].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_DL Verify: "
        << msec << " ms" << endl;

    // NIZK RE benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].backup_start = &(start[i + 16]);
        args[i].backup_end = &(end[i + 16]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            NIZK_RE_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_RE Prove: "
        << msec << " ms" << endl;
    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i + 16].tv_sec - start[i + 16].tv_sec)*1000 + 
            (end[i + 16].tv_usec - start[i + 16].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_RE Verify: "
        << msec << " ms" << endl;

    // NIZK OR benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].backup_start = &(start[i + 16]);
        args[i].backup_end = &(end[i + 16]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            NIZK_OR_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_OR Prove: "
        << msec << " ms" << endl;
    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i + 16].tv_sec - start[i + 16].tv_sec)*1000 + 
            (end[i + 16].tv_usec - start[i + 16].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_OR Verify: "
        << msec << " ms" << endl;

    // NIZK S benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].backup_start = &(start[i + 16]);
        args[i].backup_end = &(end[i + 16]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            NIZK_S_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_S Prove: "
        << msec << " ms" << endl;
    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i + 16].tv_sec - start[i + 16].tv_sec)*1000 + 
            (end[i + 16].tv_usec - start[i + 16].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_S Verify: "
        << msec << " ms" << endl;

    // NIZK RR benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].backup_start = &(start[i + 16]);
        args[i].backup_end = &(end[i + 16]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            NIZK_RR_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_RR Prove: "
        << msec << " ms" << endl;
    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i + 16].tv_sec - start[i + 16].tv_sec)*1000 + 
            (end[i + 16].tv_usec - start[i + 16].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_RR Verify: "
        << msec << " ms" << endl;

    // NIZK DLE benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].backup_start = &(start[i + 16]);
        args[i].backup_end = &(end[i + 16]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            NIZK_DLE_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i].tv_sec - start[i].tv_sec)*1000 + 
            (end[i].tv_usec - start[i].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_DLE Prove: "
        << msec << " ms" << endl;
    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += ((end[i + 16].tv_sec - start[i + 16].tv_sec)*1000 + 
            (end[i + 16].tv_usec - start[i + 16].tv_usec)/1000);
    }
    msec /= nth;
    cout << "[*] Average time for " << loop << " NIZK_DLE Verify: "
        << msec << " ms" << endl;


    cout << endl;
    cout << "--------------------- ZK proofs test ---------------------" << endl;

    // ZK shuffle benchmark
    for (int i = 0; i < nth; i++) {
        args[i].thread_id = i;
        args[i].this_loop = loop/nth;
        args[i].batch = batch/nth;
        args[i].curve = curve;
        args[i].G = G;
        args[i].q = q;
        args[i].start = &(start[i]);
        args[i].end = &(end[i]);
        args[i].backup_start = &(start[i + 16]);
        args[i].backup_end = &(end[i + 16]);
        args[i].p0 = &p0;
        args[i].p1 = &p1;
        args[i].p2 = &p2;

        pthread_create(&(ths[i]), NULL,
            ZK_shuffle_subroutine, &(args[i]));
    }
    for (int i = 0; i < nth; i++) {
        pthread_join(ths[i], NULL);
    }

    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += start[i].tv_sec;
    }
    msec /= nth;
    cout << "[*] Average time for 1 ZK shuffle Prove with " << batch << " bins: "
        << msec << " ms" << endl;
    msec = 0;
    for (int i = 0; i < nth; ++i) {
        msec += start[i + 16].tv_sec;
    }
    msec /= nth;
    cout << "[*] Average time for 1 ZK shuffle Verify with " << batch << " bins: "
        << msec << " ms" << endl;




    delete ths;
    delete args;
    BN_CTX_free(ctx);
    return 0;
}