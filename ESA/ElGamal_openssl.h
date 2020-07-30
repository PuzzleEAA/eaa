#ifndef _ELGAMAL_H
#define _ELGAMAL_H

#include <stdio.h>
#include "Tools/octetStream.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define PRINT 		true
#define LENGTH		32

#define FIRST			0
#define SECOND			1
#define NOT_SHUFFLED	0
#define SHUFFLED 		1

void pack(BIGNUM *num, BIGNUM *q, octetStream &o);
void pack(BIGNUM *num, octetStream &o);
void pack(EC_GROUP *curve, EC_POINT *point, octetStream &o);
void unpack(BIGNUM *num, octetStream &o);
void unpack(EC_GROUP *curve, EC_POINT *point, octetStream &o);

class ElGamalCiphertext
{
public:
	EC_GROUP *curve;
	EC_POINT *c1;
	EC_POINT *c2;

	ElGamalCiphertext() {
		curve = NULL;
		c1 = NULL;
		c2 = NULL;
	}
	ElGamalCiphertext(EC_GROUP *curve) {
		init(curve);
	}
	ElGamalCiphertext(const ElGamalCiphertext &tar) {
		curve = tar.curve;
		c1 = EC_POINT_dup(tar.c1, curve);
		c2 = EC_POINT_dup(tar.c2, curve);
	}

	ElGamalCiphertext& operator =(const ElGamalCiphertext &tar){
		if(this == &tar){
			return *this;
		}

		if(c1 != NULL){
			EC_POINT_free(c1);
		}

		if(c2 != NULL){
			EC_POINT_free(c2);
		}

		curve = tar.curve;
		c1 = EC_POINT_dup(tar.c1, curve);
		c2 = EC_POINT_dup(tar.c2, curve);

		return *this;
	}

	~ElGamalCiphertext() {
		EC_POINT_free(c1);
		EC_POINT_free(c2);
	}

	void init(EC_GROUP *curve) {
		this->curve = curve;
		c1 = EC_POINT_new(curve);
		c2 = EC_POINT_new(curve);
	}

	void pack(octetStream& o) {
		::pack(curve, c1, o); ::pack(curve, c2, o);
	}
	void unpack(octetStream& o) {
		::unpack(curve, c1, o); ::unpack(curve, c2, o);
	}
};

/*
	NIZK proofs classes
*/
class NIZK_DL_Proof
{
public:
	EC_GROUP *curve;
	BIGNUM *q;
	EC_POINT *T;
	BIGNUM *eta;

	NIZK_DL_Proof(EC_GROUP *curve, BIGNUM *q) {
		this->curve = curve;
		this->q = q;
		T = EC_POINT_new(curve);
		eta = BN_new();
	}
	~NIZK_DL_Proof() {
		EC_POINT_free(T);
		BN_free(eta);
	}

	void pack(octetStream& o) {
		::pack(curve, T, o);
		::pack(eta, q, o);
	}
	void unpack(octetStream& o) {
		::unpack(curve, T, o);
		::unpack(eta, o);
	}
};

class NIZK_RE_Proof
{
public:
	EC_GROUP *curve;
	BIGNUM *q;
	EC_POINT *T1, *T2;
	BIGNUM *eta;

	NIZK_RE_Proof(EC_GROUP *curve, BIGNUM *q) {
		this->curve = curve;
		this->q = q;
		T1 = EC_POINT_new(curve);
		T2 = EC_POINT_new(curve);
		eta = BN_new();
	}
	~NIZK_RE_Proof() {
		EC_POINT_free(T1);
		EC_POINT_free(T2);
		BN_free(eta);
	}

	void pack(octetStream& o) {
		::pack(curve, T1, o); ::pack(curve, T2, o);
		::pack(eta, q, o);
	}
	void unpack(octetStream& o) {
		::unpack(curve, T1, o); ::unpack(curve, T2, o);
		::unpack(eta, o);
	}
};

class NIZK_OR_Proof
{
public:
	EC_GROUP *curve;
	BIGNUM *q;
	EC_POINT *T1[2], *T2[2];
	BIGNUM *delta[2], *eta[2];

	NIZK_OR_Proof(EC_GROUP *curve, BIGNUM *q) {
		this->curve = curve;
		this->q = q;
		T1[0] = EC_POINT_new(curve); T1[1] = EC_POINT_new(curve);
		T2[0] = EC_POINT_new(curve); T2[1] = EC_POINT_new(curve);
		delta[0] = BN_new(); delta[1] = BN_new();
		eta[0] = BN_new(); eta[1] = BN_new();
	}
	NIZK_OR_Proof(const NIZK_OR_Proof &tar) {
		this->curve = tar.curve;
		this->q = tar.q;
		T1[0] = EC_POINT_dup(tar.T1[0], curve);
		T1[1] = EC_POINT_dup(tar.T1[1], curve);
		T2[0] = EC_POINT_dup(tar.T2[0], curve);
		T2[1] = EC_POINT_dup(tar.T2[1], curve);
		delta[0] = BN_dup(tar.delta[0]);
		delta[1] = BN_dup(tar.delta[1]);
		eta[0] = BN_dup(tar.eta[0]);
		eta[1] = BN_dup(tar.eta[1]);
	};
	NIZK_OR_Proof() {
		curve = NULL;
		q = NULL;
		T1[0] = NULL;
		T1[1] = NULL;
		T2[0] = NULL;
		T2[1] = NULL;
		delta[0] = NULL;
		delta[1] = NULL;
		eta[0] = NULL;
		eta[1] = NULL;
	}
/*
	~NIZK_OR_Proof() {
		EC_POINT_free(T1[0]); EC_POINT_free(T1[1]);
		EC_POINT_free(T2[0]); EC_POINT_free(T2[1]);
		BN_free(delta[0]); BN_free(delta[1]);
		BN_free(eta[0]); BN_free(eta[1]);
	}
*/
	void pack(octetStream& o) {
		::pack(curve, T1[0], o); ::pack(curve, T1[1], o);
		::pack(curve, T2[0], o); ::pack(curve, T2[1], o);
		::pack(delta[0], q, o); ::pack(delta[1], q, o);
		::pack(eta[0], q, o); ::pack(eta[1], q, o);
	}
	void unpack(octetStream& o) {
		::unpack(curve, T1[0], o); ::unpack(curve, T1[1], o);
		::unpack(curve, T2[0], o); ::unpack(curve, T2[1], o);
		::unpack(delta[0], o); ::unpack(delta[1], o);
		::unpack(eta[0], o); ::unpack(eta[1], o);
	}
};

class NIZK_S_Proof
{
public:
	NIZK_OR_Proof proofs[2];

	NIZK_S_Proof(EC_GROUP *curve, BIGNUM *q) {
		proofs[0] = NIZK_OR_Proof(curve, q);
		proofs[1] = NIZK_OR_Proof(curve, q);
	}
	~NIZK_S_Proof() {}

	void pack(octetStream& o) {
		proofs[0].pack(o);
		proofs[1].pack(o);
	}
	void unpack(octetStream& o) {
		proofs[0].unpack(o);
		proofs[1].unpack(o);
	}
};

class NIZK_RR_Proof
{
public:
	EC_GROUP *curve;
	BIGNUM *q;
	EC_POINT *T1, *T2;
	BIGNUM *eta1, *eta2;

	NIZK_RR_Proof(EC_GROUP *curve, BIGNUM *q) {
		this->curve = curve;
		this->q = q;
		T1 = EC_POINT_new(curve);
		T2 = EC_POINT_new(curve);
		eta1 = BN_new();
		eta2 = BN_new();
	}
	~NIZK_RR_Proof() {
		EC_POINT_free(T1);
		EC_POINT_free(T2);
		BN_free(eta1);
		BN_free(eta2);
	}

	void pack(octetStream& o) {
		::pack(curve, T1, o); ::pack(curve, T2, o);
		::pack(eta1, q, o); ::pack(eta2, q, o);
	}
	void unpack(octetStream& o) {
		::unpack(curve, T1, o); ::unpack(curve, T2, o);
		::unpack(eta1, o); ::unpack(eta2, o);
	}
};

class NIZK_DLE_Proof
{
public:
	EC_GROUP *curve;
	BIGNUM *q;
	EC_POINT *T1, *T2;
	BIGNUM *eta;

	NIZK_DLE_Proof(EC_GROUP *curve, BIGNUM *q) {
		this->curve = curve;
		this->q = q;
		T1 = EC_POINT_new(curve);
		T2 = EC_POINT_new(curve);
		eta = BN_new();
	}
	~NIZK_DLE_Proof() {
		EC_POINT_free(T1);
		EC_POINT_free(T2);
		BN_free(eta);
	}

	void pack(octetStream& o) {
		::pack(curve, T1, o); ::pack(curve, T2, o);
		::pack(eta, q, o);
	}
	void unpack(octetStream& o) {
		::unpack(curve, T1, o); ::unpack(curve, T2, o);
		::unpack(eta, o);
	}
};


/*
	ZK shuffle proof classes
*/
class ZK_Shuffle_Stage_1_Proof
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;
	EC_POINT *Gamma;
	vector<EC_POINT *> A, C, U, W;
	EC_POINT *Lambda1, *Lambda2;

	ZK_Shuffle_Stage_1_Proof(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		A.resize(k); C.resize(k);
		U.resize(k); W.resize(k);
		Gamma = EC_POINT_new(curve);
		for (unsigned int i = 0; i < k; i++) {
			A[i] = EC_POINT_new(curve);
			C[i] = EC_POINT_new(curve);
			U[i] = EC_POINT_new(curve);
			W[i] = EC_POINT_new(curve);
		}
		Lambda1 = EC_POINT_new(curve);
		Lambda2 = EC_POINT_new(curve);
	}
	~ZK_Shuffle_Stage_1_Proof() {
		EC_POINT_free(Gamma);
		for (unsigned int i = 0; i < k; i++) {
			EC_POINT_free(A[i]);
			EC_POINT_free(C[i]);
			EC_POINT_free(U[i]);
			EC_POINT_free(W[i]);
		}
		EC_POINT_free(Lambda1);
		EC_POINT_free(Lambda2);
	}

	void pack(octetStream& o) {
		::pack(curve, Gamma, o);
		for (unsigned int i = 0; i < k; i++) {
			::pack(curve, A[i], o);
			::pack(curve, C[i], o);
			::pack(curve, U[i], o);
			::pack(curve, W[i], o);
		}
		::pack(curve, Lambda1, o); ::pack(curve, Lambda2, o);
	}
	void unpack(octetStream& o) {
		::unpack(curve, Gamma, o);
		for (unsigned int i = 0; i < k; i++) {
			::unpack(curve, A[i], o);
			::unpack(curve, C[i], o);
			::unpack(curve, U[i], o);
			::unpack(curve, W[i], o);
		}
		::unpack(curve, Lambda1, o); ::unpack(curve, Lambda2, o);
	}
};

class ZK_Shuffle_Stage_1_Challenge
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;
	vector<BIGNUM *> vec_rho;

	ZK_Shuffle_Stage_1_Challenge(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		vec_rho.resize(k);
		for (unsigned int i = 0; i < k; i++)
			vec_rho[i] = BN_new();
	}
	~ZK_Shuffle_Stage_1_Challenge() {
		for (unsigned int i = 0; i < k; i++)
			BN_free(vec_rho[i]);
	}

	void pack(octetStream& o) {
		for (unsigned int i = 0; i < k; i++)
			::pack(vec_rho[i], q, o);
	}
	void unpack(octetStream& o) {
		for (unsigned int i = 0; i < k; i++)
			::unpack(vec_rho[i], o);
	}
};

class ZK_Shuffle_Stage_2_Proof
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;
	vector<EC_POINT *> D;

	ZK_Shuffle_Stage_2_Proof(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		D.resize(k);
		for (unsigned int i = 0; i < k; i++)
			D[i] = EC_POINT_new(curve);
	}
	~ZK_Shuffle_Stage_2_Proof() {
		for (unsigned int i = 0; i < k; i++)
			EC_POINT_free(D[i]);
	}

	void pack(octetStream& o) {
		for (unsigned int i = 0; i < k; i++)
			::pack(curve, D[i], o);
	}
	void unpack(octetStream& o) {
		for (unsigned int i = 0; i < k; i++)
			::unpack(curve, D[i], o);
	}
};

class ZK_Shuffle_Stage_3_Proof
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;
	vector<BIGNUM *> vec_sigma;
	BIGNUM *tau;

	ZK_Shuffle_Stage_3_Proof(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		vec_sigma.resize(k);
		for (unsigned int i = 0; i < k; i++)
			vec_sigma[i] = BN_new();
		tau = BN_new();
	}
	~ZK_Shuffle_Stage_3_Proof() {
		for (unsigned int i = 0; i < k; i++)
			BN_free(vec_sigma[i]);
		BN_free(tau);
	}

	void pack(octetStream& o) {
		::pack(tau, q, o);
		for (unsigned int i = 0; i < k; i++)
			::pack(vec_sigma[i], q, o);
	}
	void unpack(octetStream& o) {
		::unpack(tau, o);
		for (unsigned int i = 0; i < k; i++)
			::unpack(vec_sigma[i], o);
	}
};

/*
	ZK simple k-shuffle proof classes
*/
class ZK_SS_Stage_1_Proof
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;
	vector<EC_POINT *> Theta;

	ZK_SS_Stage_1_Proof(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		Theta.resize(2*k);
		for (unsigned int i = 0; i < 2*k; i++)
			Theta[i] = EC_POINT_new(curve);
	}
	~ZK_SS_Stage_1_Proof() {
		for (unsigned int i = 0; i < 2*k; i++)
			EC_POINT_free(Theta[i]);
	}

	void pack(octetStream& o) {
		for (unsigned int i = 0; i < 2*k; i++)
			::pack(curve, Theta[i], o);
	}
	void unpack(octetStream& o) {
		for (unsigned int i = 0; i < 2*k; i++)
			::unpack(curve, Theta[i], o);
	}
};

class ZK_SS_Stage_2_Proof
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;
	vector<BIGNUM *> alpha;

	ZK_SS_Stage_2_Proof(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		alpha.resize(2*k - 1);
		for (unsigned int i = 0; i < 2*k - 1; i++)
			alpha[i] = BN_new();
	}
	~ZK_SS_Stage_2_Proof() {
		for (unsigned int i = 0; i < 2*k - 1; i++)
			BN_free(alpha[i]);
	}

	void pack(octetStream& o) {
		for (unsigned int i = 0; i < 2*k - 1; i++)
			::pack(alpha[i], q, o);
	}
	void unpack(octetStream& o) {
		for (unsigned int i = 0; i < 2*k - 1; i++)
			::unpack(alpha[i], o);
	}
};

/*
	ZK context used to store critical vars
*/
class ZK_Shuffle_Prover_Context
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;

	BIGNUM *tau0, *v, *gamma;
	vector<BIGNUM *> vec_u, vec_w, vec_a;
	// Stage 1 proof
	ZK_Shuffle_Stage_1_Proof *stage_1_proof;

	vector<BIGNUM *> vec_b, vec_d;
	// Stage 2 proof
	ZK_Shuffle_Stage_2_Proof *stage_2_proof;

	vector<BIGNUM *> vec_r, vec_s;
	// Stage 3 proof
	ZK_Shuffle_Stage_3_Proof *stage_3_proof;

	/*
		The following vars are for simple k-shuffle proof
	*/
	vector<BIGNUM *> vec_theta;
	// Stage 1 proof of simple k-shuffle proof
	ZK_SS_Stage_1_Proof *ss_stage_1_proof;

	// Stage 2 proof of simple k-shuffle proof
	ZK_SS_Stage_2_Proof *ss_stage_2_proof;

	ZK_Shuffle_Prover_Context(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		tau0 = BN_new(); v = BN_new(); gamma = BN_new();
		vec_u.resize(k); vec_w.resize(k); vec_a.resize(k);
		stage_1_proof = new ZK_Shuffle_Stage_1_Proof(curve, k, q);
		vec_b.resize(k); vec_d.resize(k);
		stage_2_proof = new ZK_Shuffle_Stage_2_Proof(curve, k, q);
		vec_r.resize(k); vec_s.resize(k);
		stage_3_proof = new ZK_Shuffle_Stage_3_Proof(curve, k, q);
		vec_theta.resize(2*k - 1);
		ss_stage_1_proof = new ZK_SS_Stage_1_Proof(curve, k, q);
		ss_stage_2_proof = new ZK_SS_Stage_2_Proof(curve, k, q);
		for (unsigned int i = 0; i < k; i++) {
			vec_u[i] = BN_new();
			vec_w[i] = BN_new();
			vec_a[i] = BN_new();
			vec_b[i] = BN_new();
			vec_d[i] = BN_new();
			vec_r[i] = BN_new();
			vec_s[i] = BN_new();
		}
		for (unsigned int i = 0; i < 2*k - 1; i++)
			vec_theta[i] = BN_new();
	}
	~ZK_Shuffle_Prover_Context() {
		BN_free(tau0); BN_free(v); BN_free(gamma);
		delete stage_1_proof;
		delete stage_2_proof;
		delete stage_3_proof;
		delete ss_stage_1_proof;
		delete ss_stage_2_proof;
		for (unsigned int i = 0; i < k; i++) {
			BN_free(vec_u[i]);
			BN_free(vec_w[i]);
			BN_free(vec_a[i]);
			BN_free(vec_b[i]);
			BN_free(vec_d[i]);
			BN_free(vec_r[i]);
			BN_free(vec_s[i]);
		}
		for (unsigned int i = 0; i < 2*k - 1; i++)
			BN_free(vec_theta[i]);
	}
};

class ZK_Shuffle_Verifier_Context
{
public:
	unsigned int k;
	EC_GROUP *curve;
	BIGNUM *q;

	vector<EC_POINT *> B, R, S;

	// Received stage 1 proof
	ZK_Shuffle_Stage_1_Proof *stage_1_proof;
	// Stage 1 challenge
	ZK_Shuffle_Stage_1_Challenge *stage_1_challenge;

	// Received stage 2 proof
	ZK_Shuffle_Stage_2_Proof *stage_2_proof;
	// Stage 2 challenge (only a random number)
	BIGNUM *lambda;

	// Received stage 3 proof
	ZK_Shuffle_Stage_3_Proof *stage_3_proof;

	/*
		The following vars are for simple k-shuffle proof
	*/
	// Challenge for stage 1 proof (only a random number)
	BIGNUM *t;
	// Received stage 1 proof of simple k-shuffle proof
	ZK_SS_Stage_1_Proof *ss_stage_1_proof;
	
	// Challenge for stage 2 proof (only a random number)
	BIGNUM *c;

	ZK_Shuffle_Verifier_Context(EC_GROUP *curve, unsigned int k,
		BIGNUM *q) {
		this->curve = curve;
		this->k = k;
		this->q = q;
		B.resize(k);
		R.resize(k);
		S.resize(k);
		for (unsigned int i = 0; i < k; i++) {
			B[i] = EC_POINT_new(curve);
			R[i] = EC_POINT_new(curve);
			S[i] = EC_POINT_new(curve);
		}
		lambda = BN_new();
		t = BN_new();
		c = BN_new();
		stage_1_challenge = new ZK_Shuffle_Stage_1_Challenge(curve, k, q);
	}
	~ZK_Shuffle_Verifier_Context() {
		for (unsigned int i = 0; i < k; i++) {
			EC_POINT_free(B[i]);
			EC_POINT_free(R[i]);
			EC_POINT_free(S[i]);
		}
		BN_free(lambda);
		BN_free(t);
		BN_free(c);
		delete stage_1_challenge;
	}
};





class ElGamal
{
public:
	EC_GROUP *curve;
	EC_POINT *G;
	BIGNUM *q;

	BN_CTX *ctx;

//private:
public:
	BIGNUM *partial_secret_key;
public:
	EC_POINT *partial_public_key;
	vector<EC_POINT *> other_public_keys;
	EC_POINT *global_public_key;

public:
	ElGamal(unsigned int n_parties, bool print) {
		curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
		ctx = BN_CTX_new();

    	G = EC_POINT_dup(EC_GROUP_get0_generator(curve), curve);
    	q = BN_new();

    	EC_GROUP_get_order(curve, q, ctx);

    	partial_secret_key = BN_new();
    	partial_public_key = EC_POINT_new(curve);

    	other_public_keys.resize(n_parties);
    	cout << "[*] ElGamal system OK" << endl;

    	init_key_pair(PRINT);

    	if (print){
    		cout << "[*] You can print something there" << endl;
    	}
    		
	}
	ElGamal(ElGamal *ptr) {
		curve = EC_GROUP_dup(ptr->curve);
		G = EC_POINT_dup(ptr->G, curve);
		q = BN_dup(ptr->q);
		ctx = BN_CTX_new();
		partial_secret_key = BN_dup(ptr->partial_secret_key);
		partial_public_key = EC_POINT_dup(ptr->partial_public_key, curve);
		other_public_keys.resize(ptr->other_public_keys.size());
		for (unsigned int i = 0; i < other_public_keys.size(); i++)
			other_public_keys[i] = EC_POINT_dup(ptr->other_public_keys[i], curve);
		global_public_key = EC_POINT_dup(ptr->global_public_key, curve);
	}
	
	~ElGamal() {
		EC_GROUP_free(curve);
		EC_POINT_free(G);
		BN_free(q);
		BN_CTX_free(ctx);
		BN_free(partial_secret_key);
		EC_POINT_free(partial_public_key);
		for (unsigned int i = 0; i < other_public_keys.size(); i++) {
			EC_POINT_free(other_public_keys[i]);
		}
		EC_POINT_free(global_public_key);
	};
	
	void init_key_pair(bool print);
	void add_other_public_key(const EC_POINT *other_public_key,
		const unsigned int party_id);

	void encrypt(ElGamalCiphertext& ciphertext,
		const EC_POINT *M, BIGNUM *r);
	void partial_decrypt(ElGamalCiphertext& new_ciphertext,
		ElGamalCiphertext& old_ciphertext);
	void re_encrypt(ElGamalCiphertext& new_ciphertext,
		ElGamalCiphertext& old_ciphertext, BIGNUM *r);
	void randomize(ElGamalCiphertext& new_ciphertext,
		ElGamalCiphertext& old_ciphertext, BIGNUM *r);


	void NIZK_DL_Prove(NIZK_DL_Proof& proof,
		BIGNUM *secret, EC_POINT *exp_secret);
	bool NIZK_DL_Verify(NIZK_DL_Proof& proof, 
		const EC_POINT *tar_partial_public_key);

	void NIZK_RE_Prove(NIZK_RE_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext,
		const BIGNUM *r);
	bool NIZK_RE_Verify(NIZK_RE_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);

	void NIZK_OR_Prove(NIZK_OR_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2], const int b,
		const ElGamalCiphertext& old_ciphertext,
		const BIGNUM *r);
	bool NIZK_OR_Verify(NIZK_OR_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2],
		const ElGamalCiphertext& old_ciphertext);

	void NIZK_S_Prove(NIZK_S_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2],
		const ElGamalCiphertext old_ciphertexts[2],
		BIGNUM *r[2], const int isShuffled);
	bool NIZK_S_Verify(NIZK_S_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2],
		const ElGamalCiphertext old_ciphertexts[2]);

	void NIZK_RR_Prove(NIZK_RR_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext,
		const BIGNUM *re_enc_r, const BIGNUM *rand_r);
	bool NIZK_RR_Verify(NIZK_RR_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);

	void NIZK_DLE_Prove(NIZK_DLE_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);
	bool NIZK_DLE_Verify(NIZK_DLE_Proof& proof,
		const EC_POINT *tar_partial_public_key,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);


	void ZK_Shuffle_Prove_Stage_1(ZK_Shuffle_Prover_Context& context,
		const vector<BIGNUM *>& vec_beta,
		const vector<ElGamalCiphertext>& vec_new_ciphertext,
		const vector<ElGamalCiphertext>& vec_old_ciphertext);
	void ZK_Shuffle_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
		ZK_Shuffle_Stage_1_Proof *stage_1_proof);
	void ZK_Shuffle_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
		ZK_Shuffle_Stage_1_Challenge *stage_1_challenge);
	void ZK_Shuffle_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
		ZK_Shuffle_Stage_2_Proof *stage_2_proof);
	void ZK_Shuffle_Prove_Stage_3(ZK_Shuffle_Prover_Context& context,
		const vector<BIGNUM *>& vec_beta, const BIGNUM *lambda);
	void ZK_Shuffle_Verify_Stage_3(ZK_Shuffle_Verifier_Context& context,
		ZK_Shuffle_Stage_3_Proof *stage_3_proof);

	void ZK_SS_Prove_Stage_1(ZK_Shuffle_Prover_Context& context,
		const BIGNUM *t);
	void ZK_SS_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
		ZK_SS_Stage_1_Proof *ss_stage_1_proof);
	void ZK_SS_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
		const BIGNUM *c);
	bool ZK_SS_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
		ZK_SS_Stage_2_Proof *ss_stage_2_proof);
	bool ZK_Shuffle_Verify_Final(ZK_Shuffle_Verifier_Context& context,
		const vector<ElGamalCiphertext>& vec_new_ciphertext,
		const vector<ElGamalCiphertext>& vec_old_ciphertext);
};


#endif