
#ifndef _ELGAMAL_H
#define _ELGAMAL_H

#include <ctime>

#include "ecn.h"
extern "C"
{
	#include "miracl.h"
}
#include "Tools/octetStream.h"

#define PRINT 		true
#define LENGTH		(curve_bits/8)

#define FIRST			0
#define SECOND			1
#define NOT_SHUFFLED	0
#define SHUFFLED 		1

// NOTE: the first parameter of pack(const Big&, octetStream&)
// should be non-negative, given that the result returned 
// by corresponding unpack(Big&, octetStream&) is non-negative.
void pack(Big&, octetStream&);
void pack(ECn&, octetStream&);
void unpack(Big&, octetStream&);
void unpack(ECn&, octetStream&);


class ElGamalCiphertext
{
public:
	ECn c1;
	ECn c2;

	void pack(octetStream& o) {
		::pack(c1, o); ::pack(c2, o);
	}
	void unpack(octetStream& o) {
		::unpack(c1, o); ::unpack(c2, o);
	}
};

/*
	NIZK proofs classes
*/
class NIZK_DL_Proof
{
public:
	ECn T;
	Big eta;

	void pack(octetStream& o) {
		::pack(T, o);
		::pack(eta, o);
	}
	void unpack(octetStream& o) {
		::unpack(T, o);
		::unpack(eta, o);
	}
};

class NIZK_RE_Proof
{
public:
	ECn T1, T2;
	Big eta;

	void pack(octetStream& o) {
		::pack(T1, o); ::pack(T2, o);
		::pack(eta, o);
	}
	void unpack(octetStream& o) {
		::unpack(T1, o); ::unpack(T2, o);
		::unpack(eta, o);
	}
};

class NIZK_OR_Proof
{
public:
	ECn T1[2], T2[2];
	Big delta[2], eta[2];

	void pack(octetStream& o) {
		::pack(T1[0], o); ::pack(T1[1], o);
		::pack(T2[0], o); ::pack(T2[1], o);
		::pack(delta[0], o); ::pack(delta[1], o);
		::pack(eta[0], o); ::pack(eta[1], o);
	}
	void unpack(octetStream& o) {
		::unpack(T1[0], o); ::unpack(T1[1], o);
		::unpack(T2[0], o); ::unpack(T2[1], o);
		::unpack(delta[0], o); ::unpack(delta[1], o);
		::unpack(eta[0], o); ::unpack(eta[1], o);
	}
};

class NIZK_S_Proof
{
public:
	NIZK_OR_Proof proofs[2];

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
	ECn T1, T2;
	Big eta1, eta2;

	void pack(octetStream& o) {
		::pack(T1, o); ::pack(T2, o);
		::pack(eta1, o); ::pack(eta2, o);
	}
	void unpack(octetStream& o) {
		::unpack(T1, o); ::unpack(T2, o);
		::unpack(eta1, o); ::unpack(eta2, o);
	}
};

class NIZK_DLE_Proof
{
public:
	ECn T1, T2;
	Big eta;

	void pack(octetStream& o) {
		::pack(T1, o); ::pack(T2, o);
		::pack(eta, o);
	}
	void unpack(octetStream& o) {
		::unpack(T1, o); ::unpack(T2, o);
		::unpack(eta, o);
	}
};

/*
	ZK shuffle proof classes
*/
class ZK_Shuffle_Stage_1_Proof
{
public:
	ECn Gamma;
	vector<ECn> A, C, U, W;
	ECn Lambda1, Lambda2;

	void pack(octetStream& o, unsigned int k) {
		::pack(Gamma, o);
		for (unsigned int i = 0; i < k; i++)
			::pack(A[i], o);
		for (unsigned int i = 0; i < k; i++)
			::pack(C[i], o);
		for (unsigned int i = 0; i < k; i++)
			::pack(U[i], o);
		for (unsigned int i = 0; i < k; i++)
			::pack(W[i], o);
		::pack(Lambda1, o); ::pack(Lambda2, o);
	}
	void unpack(octetStream& o, unsigned int k) {
		A.resize(k);
		C.resize(k);
		U.resize(k);
		W.resize(k);

		::unpack(Gamma, o);
		for (unsigned int i = 0; i < k; i++)
			::unpack(A[i], o);
		for (unsigned int i = 0; i < k; i++)
			::unpack(C[i], o);
		for (unsigned int i = 0; i < k; i++)
			::unpack(U[i], o);
		for (unsigned int i = 0; i < k; i++)
			::unpack(W[i], o);
		::unpack(Lambda1, o); ::unpack(Lambda2, o);
	}
};

class ZK_Shuffle_Stage_1_Challenge
{
public:
	vector<Big> vec_rho;

	void pack(octetStream& o, unsigned int k) {
		for (unsigned int i = 0; i < k; i++)
			::pack(vec_rho[i], o);
	}
	void unpack(octetStream& o, unsigned int k) {
		vec_rho.resize(k);

		for (unsigned int i = 0; i < k; i++)
			::unpack(vec_rho[i], o);
	}
};

class ZK_Shuffle_Stage_2_Proof
{
public:
	vector<ECn> D;

	void pack(octetStream& o, unsigned int k) {
		for (unsigned int i = 0; i < k; i++)
			::pack(D[i], o);
	}
	void unpack(octetStream& o, unsigned int k) {
		D.resize(k);

		for (unsigned int i = 0; i < k; i++)
			::unpack(D[i], o);
	}
};

class ZK_Shuffle_Stage_3_Proof
{
public:
	vector<Big> vec_sigma;
	Big tau;

	void pack(octetStream& o, unsigned int k) {
		::pack(tau, o);
		for (unsigned int i = 0; i < k; i++)
			::pack(vec_sigma[i], o);
	}
	void unpack(octetStream& o, unsigned int k) {
		vec_sigma.resize(k);

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
	vector<ECn> Theta;

	void pack(octetStream& o, unsigned int k) {
		for (unsigned int i = 0; i < 2*k; i++)
			::pack(Theta[i], o);
	}
	void unpack(octetStream& o, unsigned int k) {
		Theta.resize(2*k);

		for (unsigned int i = 0; i < 2*k; i++)
			::unpack(Theta[i], o);
	}
};

class ZK_SS_Stage_2_Proof
{
public:
	vector<Big> alpha;

	void pack(octetStream& o, unsigned int k) {
		for (unsigned int i = 0; i < 2*k - 1; i++)
			::pack(alpha[i], o);
	}
	void unpack(octetStream& o, unsigned int k) {
		alpha.resize(2*k - 1);

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

	Big tau0, v, gamma;
	vector<Big> vec_u, vec_w, vec_a;
	// Stage 1 proof
	ZK_Shuffle_Stage_1_Proof stage_1_proof;

	vector<Big> vec_b, vec_d;
	// Stage 2 proof
	ZK_Shuffle_Stage_2_Proof stage_2_proof;

	vector<Big> vec_r, vec_s;
	// Stage 3 proof
	ZK_Shuffle_Stage_3_Proof stage_3_proof;

	/*
		The following vars are for simple k-shuffle proof
	*/
	vector<Big> vec_theta;
	// Stage 1 proof of simple k-shuffle proof
	ZK_SS_Stage_1_Proof ss_stage_1_proof;

	// Stage 2 proof of simple k-shuffle proof
	ZK_SS_Stage_2_Proof ss_stage_2_proof;
};

class ZK_Shuffle_Verifier_Context
{
public:
	unsigned int k;
	vector<ECn> B, R, S;

	// Received stage 1 proof
	ZK_Shuffle_Stage_1_Proof stage_1_proof;
	// Stage 1 challenge
	ZK_Shuffle_Stage_1_Challenge stage_1_challenge;

	// Received stage 2 proof
	ZK_Shuffle_Stage_2_Proof stage_2_proof;
	// Stage 2 challenge (only a random number)
	Big lambda;

	// Received stage 3 proof
	ZK_Shuffle_Stage_3_Proof stage_3_proof;

	/*
		The following vars are for simple k-shuffle proof
	*/
	// Challenge for stage 1 proof (only a random number)
	Big t;
	// Received stage 1 proof of simple k-shuffle proof
	ZK_SS_Stage_1_Proof ss_stage_1_proof;
	
	// Challenge for stage 2 proof (only a random number)
	Big c;
};

/*
	ElGamal scheme (distributed decryption ver.)
*/
class ElGamal
{
public:
	Big a, b, p;
	Big q;
	Big x, y;
	ECn G;

private:
	Big partial_secret_key;
public:
	ECn partial_public_key;
	vector<ECn> other_public_keys;
	ECn global_public_key;

public:
	ElGamal(const char* ecurve_file, unsigned int n_parties, bool print) {
		init_ecurve(ecurve_file, print);
		other_public_keys.resize(n_parties);
	};
	~ElGamal() {
	};

	void init_ecurve(const char *, bool print);
	void init_key_pair(const char *, bool print);

	// NOTE: this routine should be called ONLY after calling
	// init_key_pair(...)
	void add_other_public_key(const ECn& other_public_key,
		const unsigned int party_id);
	void print_curve();
	void print_key_pair();

	void encrypt(ElGamalCiphertext&, const ECn&);
	void encrypt(ElGamalCiphertext& ciphertext, const ECn& M, Big& r);
	void partial_decrypt(ElGamalCiphertext&, ElGamalCiphertext&);
	Big re_encrypt(ElGamalCiphertext&, ElGamalCiphertext&);
	Big randomize(ElGamalCiphertext&, ElGamalCiphertext&);

	// NIZK proofs
	void NIZK_DL_Prove(NIZK_DL_Proof& proof);
	void NIZK_DL_Prove(NIZK_DL_Proof& proof, Big& secret, ECn& public_knowlege);
	bool NIZK_DL_Verify(NIZK_DL_Proof& proof, const ECn& tar_partial_public_key);

	void NIZK_RE_Prove(NIZK_RE_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext,
		const Big& r);
	bool NIZK_RE_Verify(NIZK_RE_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);

	void NIZK_OR_Prove(NIZK_OR_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2], const int b,
		const ElGamalCiphertext& old_ciphertext,
		const Big& r);
	bool NIZK_OR_Verify(NIZK_OR_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2],
		const ElGamalCiphertext& old_ciphertext);

	void NIZK_S_Prove(NIZK_S_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2],
		const ElGamalCiphertext old_ciphertexts[2],
		const Big r[2], const int isShuffled);
	bool NIZK_S_Verify(NIZK_S_Proof& proof,
		const ElGamalCiphertext new_ciphertexts[2],
		const ElGamalCiphertext old_ciphertexts[2]);

	void NIZK_RR_Prove(NIZK_RR_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext,
		const Big& re_enc_r, const Big& rand_r);
	bool NIZK_RR_Verify(NIZK_RR_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);

	void NIZK_DLE_Prove(NIZK_DLE_Proof& proof,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);
	bool NIZK_DLE_Verify(NIZK_DLE_Proof& proof,
		const ECn& tar_partial_public_key,
		const ElGamalCiphertext& new_ciphertext,
		const ElGamalCiphertext& old_ciphertext);

	// ZK shuffle proofs
	void ZK_Shuffle_Prove_Stage_1(ZK_Shuffle_Prover_Context& context,
		const vector<Big>& vec_beta,
		const vector<ElGamalCiphertext>& vec_new_ciphertext,
		const vector<ElGamalCiphertext>& vec_old_ciphertext);
	void ZK_Shuffle_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
		const ZK_Shuffle_Stage_1_Proof& stage_1_proof);
	void ZK_Shuffle_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
		const ZK_Shuffle_Stage_1_Challenge& stage_1_challenge);
	void ZK_Shuffle_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
		const ZK_Shuffle_Stage_2_Proof& stage_2_proof);
	void ZK_Shuffle_Prove_Stage_3(ZK_Shuffle_Prover_Context& context,
		const vector<Big>& vec_beta, const Big& lambda);
	void ZK_Shuffle_Verify_Stage_3(ZK_Shuffle_Verifier_Context& context,
		const ZK_Shuffle_Stage_3_Proof stage_3_proof);

	// ZK simple k-shuffle proofs
	void ZK_SS_Prove_Stage_1(ZK_Shuffle_Prover_Context& context,
		const Big& t);
	void ZK_SS_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
		const ZK_SS_Stage_1_Proof& ss_stage_1_proof);
	void ZK_SS_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
		const Big& c);
	bool ZK_SS_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
		const ZK_SS_Stage_2_Proof& ss_stage_2_proof);

	// Final check of ZK shuffle proofs
	bool ZK_Shuffle_Verify_Final(ZK_Shuffle_Verifier_Context& context,
		const vector<ElGamalCiphertext>& vec_new_ciphertext,
		const vector<ElGamalCiphertext>& vec_old_ciphertext);

	
};



#endif