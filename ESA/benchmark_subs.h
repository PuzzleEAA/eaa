#ifndef _BENCHMARK
#define _BENCHMARK

typedef struct workerArgs {
    unsigned int thread_id;
    unsigned int this_loop;
    unsigned int batch;
    EC_GROUP *curve;
    EC_POINT *G;
    BIGNUM *q;
    struct timeval *start, *end;
    struct timeval *backup_start, *backup_end;

    ElGamal *p0, *p1, *p2;
}workerArgs;

void *encryption_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);
	BN_rand_range(rand, q);

	EC_POINT_mul(curve, M, NULL, G, rand, ctx);

	ElGamalCiphertext C(curve);
	gettimeofday(start, NULL);
    for (int i = 0; i < this_loop; i++)
        p0.encrypt(C, M, rc);
    gettimeofday(end, NULL);

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);

    ERR_print_errors_fp(stdout);

    pthread_exit(NULL);
}

void *partial_decryption_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);
	BN_rand_range(rand, q);

	EC_POINT_mul(curve, M, NULL, G, rand, ctx);

	ElGamalCiphertext C(curve);
	p0.encrypt(C, M, rc);

	ElGamalCiphertext C0(curve), C1(curve), C2(curve);
	gettimeofday(start, NULL);
    for (int i = 0; i < this_loop; i++) {
        p0.partial_decrypt(C0, C);
        p1.partial_decrypt(C1, C0);
        p2.partial_decrypt(C2, C1);
    }
    gettimeofday(end, NULL);

    if (EC_POINT_cmp(curve, C2.c2, M, ctx) == 0) {
    	cout << "    [Thread " << thread_id 
    		<< "] Encryption & Partial decryption: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] Encryption & Partial decryption: failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);

    ERR_print_errors_fp(stdout);

    pthread_exit(NULL);
}

void *re_encryption_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);
	BN_rand_range(rand, q);

	EC_POINT_mul(curve, M, NULL, G, rand, ctx);

	ElGamalCiphertext C(curve), RC(curve);
	ElGamalCiphertext C0(curve), C1(curve), C2(curve);
	p0.encrypt(C, M, rc);
	gettimeofday(start, NULL);
    for (int i = 0; i < this_loop; i++)
        p0.re_encrypt(RC, C, rc);
    gettimeofday(end, NULL);

    p0.partial_decrypt(C0, RC);
    p1.partial_decrypt(C1, C0);
    p2.partial_decrypt(C2, C1);

    if (EC_POINT_cmp(curve, C2.c2, M, ctx) == 0) {
    	cout << "    [Thread " << thread_id 
    		<< "] Re-encryption: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] Re-encryption: failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);

    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *randomization_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);
	
	EC_POINT_set_to_infinity(curve, M);

	ElGamalCiphertext C(curve), RNDC(curve);
	ElGamalCiphertext C0(curve), C1(curve), C2(curve);
	p0.encrypt(C, M, rc);
	gettimeofday(start, NULL);
    for (int i = 0; i < this_loop; i++)
        p0.randomize(RNDC, C, rc);
    gettimeofday(end, NULL);

    p0.partial_decrypt(C0, RNDC);
    p1.partial_decrypt(C1, C0);
    p2.partial_decrypt(C2, C1);

    if (EC_POINT_cmp(curve, C2.c2, M, ctx) == 0) {
    	cout << "    [Thread " << thread_id 
    		<< "] Randomization: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] Randomization: failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);
    
    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *NIZK_DL_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	struct timeval *backup_start = params->backup_start;
	struct timeval *backup_end = params->backup_end;
	octetStream o;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	NIZK_DL_Proof proof(curve, q), proof_recv(curve, q);

	gettimeofday(start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p0.NIZK_DL_Prove(proof, p0.partial_secret_key,
			p0.partial_public_key);
	}
    gettimeofday(end, NULL);

    gettimeofday(backup_start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p1.NIZK_DL_Verify(proof,
			p1.other_public_keys[0]);
	}
    gettimeofday(backup_end, NULL);


    p0.NIZK_DL_Prove(proof, p0.partial_secret_key,
		p0.partial_public_key);

    proof.pack(o);
	proof_recv.unpack(o);

	bool flag = true;
	flag &= p1.NIZK_DL_Verify(proof_recv,
		p1.other_public_keys[0]);
    flag &= p2.NIZK_DL_Verify(proof_recv,
		p2.other_public_keys[0]);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_DL: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_DL: failed!" << endl;
    }

    
    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *NIZK_RE_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	struct timeval *backup_start = params->backup_start;
	struct timeval *backup_end = params->backup_end;
	octetStream o;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);

	NIZK_RE_Proof proof(curve, q), proof_recv(curve, q);

	ElGamalCiphertext C0(curve), C1(curve);
	BN_rand_range(rand, q);
	EC_POINT_mul(curve, M, NULL, G, rand, ctx);
	p0.encrypt(C0, M, rc);
	p0.re_encrypt(C1, C0, rc);

	gettimeofday(start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p0.NIZK_RE_Prove(proof, C1, C0, rc);
	}
    gettimeofday(end, NULL);

    gettimeofday(backup_start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p1.NIZK_RE_Verify(proof, C1, C0);
	}
    gettimeofday(backup_end, NULL);

	p0.NIZK_RE_Prove(proof, C1, C0, rc);

	proof.pack(o);
	proof_recv.unpack(o);

	bool flag = true;
	flag &= p1.NIZK_RE_Verify(proof_recv, C1, C0);
	flag &= p2.NIZK_RE_Verify(proof_recv, C1, C0);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_RE: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_RE: failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);
    
    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *NIZK_OR_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	struct timeval *backup_start = params->backup_start;
	struct timeval *backup_end = params->backup_end;
	octetStream o;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);

	NIZK_OR_Proof proof(curve, q), proof_recv(curve, q);

	ElGamalCiphertext C0(curve), C1(curve), C2(curve);
	BN_rand_range(rand, q);
	EC_POINT_mul(curve, M, NULL, G, rand, ctx);
	p0.encrypt(C0, M, rc);
	BN_rand_range(rand, q);
	EC_POINT_mul(curve, M, NULL, G, rand, ctx);
	p0.encrypt(C2, M, rc);
	p0.re_encrypt(C1, C0, rc);
	
	ElGamalCiphertext Cs[2] = { C1, C2 };

	gettimeofday(start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p0.NIZK_OR_Prove(proof, Cs, FIRST, C0, rc);
	}
    gettimeofday(end, NULL);

    gettimeofday(backup_start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p1.NIZK_OR_Verify(proof, Cs, C0);
	}
    gettimeofday(backup_end, NULL);

    // Case 1
	p0.NIZK_OR_Prove(proof, Cs, FIRST, C0, rc);

	proof.pack(o);
	proof_recv.unpack(o);

	bool flag = true;
	flag &= p1.NIZK_OR_Verify(proof_recv, Cs, C0);
	flag &= p2.NIZK_OR_Verify(proof_recv, Cs, C0);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_OR (case 1): OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_OR (case 1): failed!" << endl;
    }

    ElGamalCiphertext Cs_inv[2] = { C2, C1 };

    // Case 2
    p0.NIZK_OR_Prove(proof, Cs_inv, SECOND, C0, rc);

	proof.pack(o);
	proof_recv.unpack(o);

	flag = true;
	flag &= p1.NIZK_OR_Verify(proof_recv, Cs_inv, C0);
	flag &= p2.NIZK_OR_Verify(proof_recv, Cs_inv, C0);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_OR (case 2): OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_OR (case 2): failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);
    
    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *NIZK_S_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	struct timeval *backup_start = params->backup_start;
	struct timeval *backup_end = params->backup_end;
	octetStream o;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rcs[2];
	rcs[0] = BN_new();
	rcs[1] = BN_new();
	EC_POINT *M = EC_POINT_new(curve);

	ElGamalCiphertext C01(curve), C02(curve);
	ElGamalCiphertext C1(curve), C2(curve);
	BN_rand_range(rand, q);
	EC_POINT_mul(curve, M, NULL, G, rand, ctx);
	p0.encrypt(C01, M, rcs[0]);
	p0.re_encrypt(C1, C01, rcs[0]);

	BN_rand_range(rand, q);
	EC_POINT_mul(curve, M, NULL, G, rand, ctx);
	p0.encrypt(C02, M, rcs[1]);
	p0.re_encrypt(C2, C02, rcs[1]);

	ElGamalCiphertext old_Cs[2] = { C01, C02 };
	
	ElGamalCiphertext Cs[2] = { C1, C2 };
	
	NIZK_S_Proof proof(curve, q), proof_recv(curve, q);

	gettimeofday(start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p0.NIZK_S_Prove(proof, Cs, old_Cs, rcs, NOT_SHUFFLED);
	}
    gettimeofday(end, NULL);

    gettimeofday(backup_start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p1.NIZK_S_Verify(proof, Cs, old_Cs);
	}
    gettimeofday(backup_end, NULL);

    // Case 1
	p0.NIZK_S_Prove(proof, Cs, old_Cs, rcs, NOT_SHUFFLED);
	proof.pack(o);

	proof_recv.unpack(o);

	bool flag = true;
	flag &= p1.NIZK_S_Verify(proof_recv, Cs, old_Cs);
	flag &= p2.NIZK_S_Verify(proof_recv, Cs, old_Cs);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_S (case 1): OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_S (case 1): failed!" << endl;
    }

    ElGamalCiphertext Cs_inv[2] = { C2, C1 };

    // Case 2
    p0.NIZK_S_Prove(proof, Cs_inv, old_Cs, rcs, SHUFFLED);

	proof.pack(o);
	proof_recv.unpack(o);

	flag = true;
	flag &= p1.NIZK_S_Verify(proof_recv, Cs_inv, old_Cs);
	flag &= p2.NIZK_S_Verify(proof_recv, Cs_inv, old_Cs);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_S (case 2): OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_S (case 2): failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rcs[0]);
    BN_free(rcs[1]);
    EC_POINT_free(M);
    
    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *NIZK_RR_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	struct timeval *backup_start = params->backup_start;
	struct timeval *backup_end = params->backup_end;
	octetStream o;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc1 = BN_new();
	BIGNUM *rc2 = BN_new();
	EC_POINT *M = EC_POINT_new(curve);

	NIZK_RR_Proof proof(curve, q), proof_recv(curve, q);

	ElGamalCiphertext C0(curve), C1(curve), C2(curve);
	BN_rand_range(rand, q);
	EC_POINT_mul(curve, M, NULL, G, rand, ctx);
	p0.encrypt(C0, M, rc1);
	p0.re_encrypt(C1, C0, rc1);
	p0.randomize(C2, C1, rc2);

	gettimeofday(start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p0.NIZK_RR_Prove(proof, C2, C0, rc1, rc2);
	}
    gettimeofday(end, NULL);

    gettimeofday(backup_start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p1.NIZK_RR_Verify(proof, C2, C0);
	}
    gettimeofday(backup_end, NULL);

	p0.NIZK_RR_Prove(proof, C2, C0, rc1, rc2);

	proof.pack(o);
	proof_recv.unpack(o);

	bool flag = true;
	flag &= p1.NIZK_RR_Verify(proof, C2, C0);
	flag &= p2.NIZK_RR_Verify(proof, C2, C0);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_RR: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_RR: failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc1);
    BN_free(rc2);
    EC_POINT_free(M);

    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *NIZK_DLE_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	struct timeval *backup_start = params->backup_start;
	struct timeval *backup_end = params->backup_end;
	octetStream o;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);

	NIZK_DLE_Proof proof(curve, q), proof_recv(curve, q);

	ElGamalCiphertext C0(curve), C1(curve);
	BN_rand_range(rand, q);
	EC_POINT_mul(curve, M, NULL, G, rand, ctx);
	p0.encrypt(C0, M, rc);
	p0.partial_decrypt(C1, C0);

	gettimeofday(start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p0.NIZK_DLE_Prove(proof, C1, C0);
	}
    gettimeofday(end, NULL);

    gettimeofday(backup_start, NULL);
	for (int i = 0; i < this_loop; i++) {
		p1.NIZK_DLE_Verify(proof, p1.other_public_keys[0], C1, C0);
	}
    gettimeofday(backup_end, NULL);

	p0.NIZK_DLE_Prove(proof, C1, C0);

	proof.pack(o);
	proof_recv.unpack(o);

	bool flag = true;
	flag &= p1.NIZK_DLE_Verify(proof_recv, 
		p1.other_public_keys[0], C1, C0);
	flag &= p2.NIZK_DLE_Verify(proof_recv, 
		p1.other_public_keys[0], C1, C0);

    if (flag) {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_DLE: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] NIZK_DLE: failed!" << endl;
    }

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);
    
    ERR_print_errors_fp(stdout);
	
    pthread_exit(NULL);
}

void *ZK_shuffle_subroutine(void *args) {

	workerArgs *params = (workerArgs*)args;

	unsigned int thread_id = params->thread_id;
	unsigned int this_loop = params->this_loop;
	unsigned int k = params->batch;
	EC_GROUP *curve = params->curve;
	EC_POINT *G = params->G;
	BIGNUM *q = params->q;
	struct timeval *start = params->start;
	struct timeval *end = params->end;
	struct timeval *backup_start = params->backup_start;
	struct timeval *backup_end = params->backup_end;
	octetStream o;
	ElGamal p0(params->p0);
	ElGamal p1(params->p1);
	ElGamal p2(params->p2);

	struct timeval inside_start, inside_end;
	unsigned long long prove_t = 0, verify_t = 0;

	// First two parties should have the same k
	ZK_Shuffle_Prover_Context pctx(curve, k, q);
	ZK_Shuffle_Verifier_Context vctx(curve, k, q);

	vector<BIGNUM *> vec_beta;
	vec_beta.resize(k);
	for (int i = 0; i < k; i++)
		vec_beta[i] = BN_new();
	vector<ElGamalCiphertext> vec_old_ciphertext, vec_new_ciphertext;
	vec_old_ciphertext.resize(k);
	vec_new_ciphertext.resize(k);

	BN_CTX* ctx = BN_CTX_new();
	BIGNUM *rand = BN_new();
	BIGNUM *rc = BN_new();
	EC_POINT *M = EC_POINT_new(curve);

	for (int i = 0; i < k; i++) {
		BN_rand_range(rand, q);
		EC_POINT_mul(curve, M, NULL, G, rand, ctx);
		vec_old_ciphertext[i].init(curve);
		vec_new_ciphertext[i].init(curve);
		p0.encrypt(vec_old_ciphertext[i], M, rc);
		p0.re_encrypt(vec_new_ciphertext[i],
			vec_old_ciphertext[i], vec_beta[i]);
	}

	// Secondly transfer the ciphertext vectors
	vector<ElGamalCiphertext> vec_old_ciphertext_recv, vec_new_ciphertext_recv;
	vec_old_ciphertext_recv.resize(k);
	vec_new_ciphertext_recv.resize(k);

	for (int i = 0; i < k; i++) {
		vec_old_ciphertext_recv[i].init(curve);
		vec_old_ciphertext[i].pack(o);
		vec_old_ciphertext_recv[i].unpack(o);

		vec_new_ciphertext_recv[i].init(curve);
		vec_new_ciphertext[i].pack(o);
		vec_new_ciphertext_recv[i].unpack(o);
	}

	cout << "    [Thread " << thread_id 
    		<< "] ZK shuffle setup: OK" << endl;

	// Thirdly interact with each other
	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p0.ZK_Shuffle_Prove_Stage_1(pctx,						// Prove
		vec_beta,
		vec_new_ciphertext, vec_old_ciphertext);

	gettimeofday(&inside_end, NULL);

	prove_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	ZK_Shuffle_Stage_1_Proof proof1(curve, k, q);			// Fake interaction
	pctx.stage_1_proof->pack(o);
	proof1.unpack(o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p1.ZK_Shuffle_Verify_Stage_1(vctx,						// Verify
		&proof1);

	gettimeofday(&inside_end, NULL);

	verify_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	ZK_Shuffle_Stage_1_Challenge challenge1(curve, k, q);	// Fake interaction
	vctx.stage_1_challenge->pack(o);
	challenge1.unpack(o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p0.ZK_Shuffle_Prove_Stage_2(pctx,						// Prove
		&challenge1);

	gettimeofday(&inside_end, NULL);

	prove_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	ZK_Shuffle_Stage_2_Proof proof2(curve, k, q);			// Fake interaction
	pctx.stage_2_proof->pack(o);
	proof2.unpack(o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p1.ZK_Shuffle_Verify_Stage_2(vctx,						// Verify
		&proof2);

	gettimeofday(&inside_end, NULL);

	verify_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	BIGNUM *lambda = BN_new();								// Fake interaction
	pack(vctx.lambda, q, o);
	unpack(lambda, o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p0.ZK_Shuffle_Prove_Stage_3(pctx,						// Prove
		vec_beta, lambda);

	gettimeofday(&inside_end, NULL);

	prove_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	ZK_Shuffle_Stage_3_Proof proof3(curve, k, q);			// Fake interaction
	pctx.stage_3_proof->pack(o);
	proof3.unpack(o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p1.ZK_Shuffle_Verify_Stage_3(vctx,						// Verify
		&proof3);

	gettimeofday(&inside_end, NULL);

	verify_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	BIGNUM *t = BN_new();									// Fake interaction
	pack(vctx.t, q, o);
	unpack(t, o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p0.ZK_SS_Prove_Stage_1(pctx, t);						// Prove

	gettimeofday(&inside_end, NULL);

	prove_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	ZK_SS_Stage_1_Proof proof4(curve, k, q);				// Fake interaction
	pctx.ss_stage_1_proof->pack(o);
	proof4.unpack(o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p1.ZK_SS_Verify_Stage_1(vctx,							// Verify
		&proof4);

	gettimeofday(&inside_end, NULL);

	verify_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	BIGNUM *c = BN_new();									// Fake interaction
	pack(vctx.c, q, o);
	unpack(c, o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	p0.ZK_SS_Prove_Stage_2(pctx, c);						// Prove

	gettimeofday(&inside_end, NULL);

	prove_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	ZK_SS_Stage_2_Proof proof5(curve, k, q);				// Fake interaction
	pctx.ss_stage_2_proof->pack(o);
	proof5.unpack(o);

	ERR_print_errors_fp(stdout);

	gettimeofday(&inside_start, NULL);

	bool flag1 = p1.ZK_SS_Verify_Stage_2(vctx,				// Two final checks
		&proof5);

	ERR_print_errors_fp(stdout);

	bool flag2 = p1.ZK_Shuffle_Verify_Final(vctx,
		vec_new_ciphertext_recv,
		vec_old_ciphertext_recv);

	gettimeofday(&inside_end, NULL);

	verify_t += ((inside_end.tv_sec - inside_start.tv_sec)*1000 + 
            (inside_end.tv_usec - inside_start.tv_usec)/1000);

	ERR_print_errors_fp(stdout);

	start->tv_sec = prove_t;
	backup_start->tv_sec = verify_t;


    if ((flag1 == true) && (flag2 == true)) {
    	cout << "    [Thread " << thread_id 
    		<< "] ZK shuffle: OK" << endl;
    }
    else {
    	cout << "    [Thread " << thread_id 
    		<< "] ZK shuffle: failed!" << endl;
    }

    gettimeofday(end, NULL);

    BN_CTX_free(ctx);
    BN_free(rand);
    BN_free(rc);
    EC_POINT_free(M);

    for (int i = 0; i < k; i++)
		BN_free(vec_beta[i]);

	BN_free(lambda);
	BN_free(t);
	BN_free(c);
    
    ERR_print_errors_fp(stdout);

    pthread_exit(NULL);
}



#endif