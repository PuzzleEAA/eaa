/*
	
*/

#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#include "ElGamal.h"

// Static vars
int curve_bits;


// Your customized permutation
// NOTE:
// 1. Random generator should be used. This random
//    generator should be stored in ZK_Shuffle_Prove_Context
//    as part of the secret knowledge to be proved;
// 2. It should be a permutation that will not return
//    identical output indices for any two different
//    input indices.
unsigned int Pi(unsigned int index) {
	return index;
}
unsigned int Pi_inv(unsigned int index) {
	return index;
}




/*
	Some Initialization routines
*/
void ElGamal::init_ecurve(const char *ecurve_file, bool print) {
	
	cout << "[*] Initializing my curve ..." << endl;
	// Load NIST P-256 curve
	ifstream params(ecurve_file);
	params >> curve_bits;
	
    params >> p >> a >> b 
    	>> q 
    	>> x >> y;

    if (print) print_curve();

    ecurve(a, b, p, MR_PROJECTIVE);
    G = ECn(x, y);
    cout << "[*] Curve OK" << endl;

    // Initialize random generator
    irand((unsigned)time(NULL));
}

void ElGamal::init_key_pair(const char *key_file, bool print) {

	ifstream in_key(key_file);
	Big pub_x;
	int lsb;
	if (!in_key.is_open()) {
		cout << "[!] Warning: no pre-computed key pair" << endl;
		cout << "[*] Generating new key pair ..." << endl;
		ofstream out_key(key_file);
		partial_secret_key = rand(q);
		partial_public_key = partial_secret_key*G;
		lsb = partial_public_key.get(pub_x);
		pub_x %= q;
		out_key << partial_secret_key << endl
			<< pub_x << endl << lsb << endl;
		if (print) print_key_pair();
		out_key.close();
	}
	else {
		cout << "[*] Loading key pair ..." << endl;
		in_key >> partial_secret_key;
		in_key >> pub_x >> lsb;
		partial_public_key.set(pub_x, lsb);
		if (print) print_key_pair();
	}
	global_public_key = partial_public_key;
	in_key.close();
}

void ElGamal::add_other_public_key(const ECn& other_public_key,
	const unsigned int party_id) {

	other_public_keys[party_id] = other_public_key;
	global_public_key += other_public_key;
}

void ElGamal::print_curve() {

	cout << "------------------------------ Curve Info ------------------------------" << endl;
	cout << "p = " << p << endl;
	cout << "a = " << a << endl;
	cout << "b = " << b << endl;
	cout << "q = " << q << endl;
	cout << "G = (x, y):" << endl;
	cout << "  x = " << x << endl;
	cout << "  y = " << y << endl;
	cout << "------------------------------------------------------------------------" << endl;
}

void ElGamal::print_key_pair() {

	Big pub_x, pub_y;
	partial_public_key.get(pub_x, pub_y);
	cout << "------------------------------- Key Info -------------------------------" << endl;
	cout << "Priv. Key:" << endl;
		cout << "  d = " << partial_secret_key << endl;
		cout << "Pub. Key:" << endl;
		cout << "  x = " << pub_x << endl;
		cout << "  y = " << pub_y << endl;
	cout << "------------------------------------------------------------------------" << endl;
}

/*
	ElGamal scheme (distributed decryption ver.)
*/
void ElGamal::encrypt(ElGamalCiphertext& ciphertext,
	const ECn& M) {

	Big r = rand(q);
	ciphertext.c1 = r*G;
	ciphertext.c2 = r*global_public_key;
	ciphertext.c2 += M;
}

void ElGamal::encrypt(ElGamalCiphertext& ciphertext,
	const ECn& M, Big& r) {

	r = rand(q);
	ciphertext.c1 = r*G;
	ciphertext.c2 = r*global_public_key;
	ciphertext.c2 += M;
}


void ElGamal::partial_decrypt(ElGamalCiphertext& new_ciphertext,
	ElGamalCiphertext& old_ciphertext) {

	new_ciphertext.c1 = old_ciphertext.c1;
	new_ciphertext.c2 = old_ciphertext.c2;
	new_ciphertext.c2 -= partial_secret_key*old_ciphertext.c1;
}

Big ElGamal::re_encrypt(ElGamalCiphertext& new_ciphertext,
	ElGamalCiphertext& old_ciphertext) {

	Big r = rand(q);
	new_ciphertext.c1 = old_ciphertext.c1;
	new_ciphertext.c1 += r*G;
	new_ciphertext.c2 = old_ciphertext.c2;
	new_ciphertext.c2 += r*global_public_key;

	return r;
}

Big ElGamal::randomize(ElGamalCiphertext& new_ciphertext,
	ElGamalCiphertext& old_ciphertext) {

	Big r = rand(q);
	new_ciphertext.c1 = r*old_ciphertext.c1;
	new_ciphertext.c2 = r*old_ciphertext.c2;

	return r;
}

/*
	NIZKs
*/
void ElGamal::NIZK_DL_Prove(NIZK_DL_Proof& proof) {

	Big gamma = rand(q);
	proof.T = gamma*G;

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*3];	memset(buffer, 0, LENGTH*3);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = partial_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb3 = proof.T.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb3);
	for (int i = 0; i < LENGTH*3; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	proof.eta = from_binary(LENGTH, temp);
	proof.eta *= partial_secret_key;
	proof.eta %= q;
	proof.eta += gamma;
	proof.eta %= q;
	if (proof.eta < 0)
		proof.eta += q;
}

void ElGamal::NIZK_DL_Prove(NIZK_DL_Proof& proof, Big& secret, ECn& public_knowlege) {

	Big gamma = rand(q);
	proof.T = gamma*G;

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*3];	memset(buffer, 0, LENGTH*3);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = public_knowlege.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb3 = proof.T.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb3);
	for (int i = 0; i < LENGTH*3; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	proof.eta = from_binary(LENGTH, temp);
	proof.eta *= secret;
	proof.eta %= q;
	proof.eta += gamma;
	proof.eta %= q;
	if (proof.eta < 0)
		proof.eta += q;
}



bool ElGamal::NIZK_DL_Verify(NIZK_DL_Proof& proof, const ECn& tar_partial_public_key) {

	ECn left = proof.eta*G;
	
	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*3];	memset(buffer, 0, LENGTH*3);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = tar_partial_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb3 = proof.T.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb3);
	for (int i = 0; i < LENGTH*3; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	Big delta = from_binary(LENGTH, temp);

	ECn right = delta*tar_partial_public_key;
	right += proof.T;

	if (left == right) return true;
	else return false;
}

void ElGamal::NIZK_RE_Prove(NIZK_RE_Proof& proof,
	const ElGamalCiphertext& new_ciphertext, const ElGamalCiphertext& old_ciphertext,
	const Big& r) {

	Big gamma = rand(q);
	proof.T1 = gamma*G;
	proof.T2 = gamma*global_public_key;

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*8];	memset(buffer, 0, LENGTH*8);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = global_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb5 = proof.T1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb6 = proof.T2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb5);
	shs256_process(&sh, lsb6);
	for (int i = 0; i < LENGTH*8; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	proof.eta = from_binary(LENGTH, temp);
	proof.eta *= r;
	proof.eta %= q;
	proof.eta += gamma;
	proof.eta %= q;

	if (proof.eta < 0)
		proof.eta += q;
}

bool ElGamal::NIZK_RE_Verify(NIZK_RE_Proof& proof,
	const ElGamalCiphertext& new_ciphertext, const ElGamalCiphertext& old_ciphertext) {

	ECn left1 = proof.eta*G;
	ECn left2 = proof.eta*global_public_key;

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*8];	memset(buffer, 0, LENGTH*8);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = global_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb5 = proof.T1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb6 = proof.T2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb5);
	shs256_process(&sh, lsb6);
	for (int i = 0; i < LENGTH*8; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	Big delta = from_binary(LENGTH, temp);

	ECn right1 = new_ciphertext.c1;
	right1 -= old_ciphertext.c1;
	right1 *= delta;
	right1 += proof.T1;

	ECn right2 = new_ciphertext.c2;
	right2 -= old_ciphertext.c2;
	right2 *= delta;
	right2 += proof.T2;

	if ((left1 == right1) && (left2 == right2)) return true;
	else return false;
}

void ElGamal::NIZK_OR_Prove(NIZK_OR_Proof& proof,
	const ElGamalCiphertext new_ciphertexts[2], const int b,
	const ElGamalCiphertext& old_ciphertext,
	const Big& r) {

	Big gamma = rand(q);
	Big delta_other = rand(q);
	Big eta_other = rand(q);

	if ((b == 0) || (b == 1)) {
		proof.T1[b] = gamma*G;
		proof.T2[b] = gamma*global_public_key;

		proof.T1[1-b] = eta_other*G;
		ECn _temp1 = new_ciphertexts[1-b].c1;
		_temp1 -= old_ciphertext.c1;
		_temp1 *= delta_other;
		proof.T1[1-b] -= _temp1;

		proof.T2[1-b] = eta_other*global_public_key;
		ECn _temp2 = new_ciphertexts[1-b].c2;
		_temp2 -= old_ciphertext.c2;
		_temp2 *= delta_other;
		proof.T2[1-b] -= _temp2;
	}
	else {
		cout << "[!] Fatal error in NIZK_OR_Prove(...): invalid b = " << b << endl;
		throw;
	}

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*12];	memset(buffer, 0, LENGTH*12);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = global_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = new_ciphertexts[0].c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = new_ciphertexts[0].c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertexts[1].c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertexts[1].c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb51 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb52 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);
	int lsb6 = proof.T1[0].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*8, TRUE);
	int lsb7 = proof.T2[0].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*9, TRUE);
	int lsb8 = proof.T1[1].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*10, TRUE);
	int lsb9 = proof.T2[1].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*11, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb51);
	shs256_process(&sh, lsb52);
	shs256_process(&sh, lsb6);
	shs256_process(&sh, lsb7);
	shs256_process(&sh, lsb8);
	shs256_process(&sh, lsb9);
	for (int i = 0; i < LENGTH*12; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	char temp_other[LENGTH];
	to_binary(delta_other, LENGTH, temp_other, TRUE);

	// Perform xor operation
	for (int i = 0; i < LENGTH; i++) {
		temp[i] ^= temp_other[i];
	}

	proof.delta[b] = from_binary(LENGTH, temp);
	proof.delta[1-b] = delta_other;

	proof.eta[b] = (r*proof.delta[b] + gamma)%q;
	proof.eta[1-b] = eta_other;
}

bool ElGamal::NIZK_OR_Verify(NIZK_OR_Proof& proof,
	const ElGamalCiphertext new_ciphertexts[2],
	const ElGamalCiphertext& old_ciphertext) {

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*12];	memset(buffer, 0, LENGTH*12);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = global_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = new_ciphertexts[0].c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = new_ciphertexts[0].c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertexts[1].c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertexts[1].c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb51 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb52 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);
	int lsb6 = proof.T1[0].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*8, TRUE);
	int lsb7 = proof.T2[0].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*9, TRUE);
	int lsb8 = proof.T1[1].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*10, TRUE);
	int lsb9 = proof.T2[1].get(x);
	to_binary(x, LENGTH, buffer + LENGTH*11, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb51);
	shs256_process(&sh, lsb52);
	shs256_process(&sh, lsb6);
	shs256_process(&sh, lsb7);
	shs256_process(&sh, lsb8);
	shs256_process(&sh, lsb9);
	for (int i = 0; i < LENGTH*12; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	char temp_0[LENGTH], temp_1[LENGTH];
	to_binary(proof.delta[0], LENGTH, temp_0, TRUE);
	to_binary(proof.delta[1], LENGTH, temp_1, TRUE);

	for (int i = 0; i < LENGTH; i++)
		if (temp[i] != (temp_0[i] ^ temp_1[i]))
			return false;

	ECn left1[2], left2[2];
	ECn right1[2], right2[2];

	for (int i = 0; i < 2; i++) {
		left1[i] = proof.eta[i]*G;
		left2[i] = proof.eta[i]*global_public_key;

		right1[i] = new_ciphertexts[i].c1;
		right1[i] -= old_ciphertext.c1;
		right1[i] *= proof.delta[i];
		right1[i] += proof.T1[i];

		right2[i] = new_ciphertexts[i].c2;
		right2[i] -= old_ciphertext.c2;
		right2[i] *= proof.delta[i];
		right2[i] += proof.T2[i];
	}

	if ((left1[0] == right1[0]) && (left2[0] == right2[0]) && 
		(left1[1] == right1[1]) && (left2[1] == right2[1]))
		return true;
	else return false;
}

void ElGamal::NIZK_S_Prove(NIZK_S_Proof& proof,
	const ElGamalCiphertext new_ciphertexts[2],
	const ElGamalCiphertext old_ciphertexts[2],
	const Big r[2], const int isShuffled) {

	if ((isShuffled != 0) && (isShuffled != 1)) {
		cout << "[!] Fatal error in NIZK_S_Prove(...): shuffle flag = " << isShuffled << endl;
		throw;
	}

	NIZK_OR_Prove(proof.proofs[0], new_ciphertexts, isShuffled,
		old_ciphertexts[0],
		r[0]);
	NIZK_OR_Prove(proof.proofs[1], new_ciphertexts, 1-isShuffled,
		old_ciphertexts[1],
		r[1]);
}

bool ElGamal::NIZK_S_Verify(NIZK_S_Proof& proof,
	const ElGamalCiphertext new_ciphertexts[2],
	const ElGamalCiphertext old_ciphertexts[2]) {

	return (NIZK_OR_Verify(proof.proofs[0], new_ciphertexts, old_ciphertexts[0])
			&& NIZK_OR_Verify(proof.proofs[1], new_ciphertexts, old_ciphertexts[1]));
}

void ElGamal::NIZK_RR_Prove(NIZK_RR_Proof& proof,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext,
	const Big& re_enc_r, const Big& rand_r) {

	Big gamma1 = rand(q), gamma2 = rand(q);

	proof.T1 = gamma1*old_ciphertext.c1;
	proof.T1 += gamma2*G;
	proof.T2 = gamma1*old_ciphertext.c2;
	proof.T2 += gamma2*global_public_key;

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*8];	memset(buffer, 0, LENGTH*8);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = global_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb5 = proof.T1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb6 = proof.T2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb5);
	shs256_process(&sh, lsb6);
	for (int i = 0; i < LENGTH*8; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	proof.eta1 = from_binary(LENGTH, temp);
	proof.eta1 *= rand_r;
	proof.eta1 %= q;
	proof.eta1 += gamma1;
	proof.eta1 %= q;
	if (proof.eta1 < 0)
		proof.eta1 += q;

	proof.eta2 = from_binary(LENGTH, temp);
	proof.eta2 *= rand_r;
	proof.eta2 %= q;
	proof.eta2 *= re_enc_r;
	proof.eta2 %= q;
	proof.eta2 += gamma2;
	proof.eta2 %= q;
	if (proof.eta2 < 0)
		proof.eta2 += q;
}

bool ElGamal::NIZK_RR_Verify(NIZK_RR_Proof& proof,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext) {

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*8];	memset(buffer, 0, LENGTH*8);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = global_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb5 = proof.T1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb6 = proof.T2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb5);
	shs256_process(&sh, lsb6);
	for (int i = 0; i < LENGTH*8; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	Big delta = from_binary(LENGTH, temp);

	ECn left1 = proof.eta1*old_ciphertext.c1;
	left1 += proof.eta2*G;
	ECn left2 = proof.eta1*old_ciphertext.c2;
	left2 += proof.eta2*global_public_key;

	ECn right1 = delta*new_ciphertext.c1;
	right1 += proof.T1;
	ECn right2 = delta*new_ciphertext.c2;
	right2 += proof.T2;

	if ((left1 == right1) && (left2 == right2)) return true;
	else return false;
}

void ElGamal::NIZK_DLE_Prove(NIZK_DLE_Proof& proof,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext) {

	Big gamma = rand(q);

	proof.T1 = gamma*old_ciphertext.c1;
	proof.T2 = gamma*G;

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*8];	memset(buffer, 0, LENGTH*8);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = partial_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb5 = proof.T1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb6 = proof.T2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb5);
	shs256_process(&sh, lsb6);
	for (int i = 0; i < LENGTH*8; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	proof.eta = from_binary(LENGTH, temp);
	proof.eta *= partial_secret_key;
	proof.eta %= q;
	proof.eta += gamma;
	proof.eta %= q;
	if (proof.eta < 0)
		proof.eta += q;
}

bool ElGamal::NIZK_DLE_Verify(NIZK_DLE_Proof& proof,
	const ECn& tar_partial_public_key,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext) {

	sha256 sh;
	shs256_init(&sh);
	char buffer[LENGTH*8];	memset(buffer, 0, LENGTH*8);
	char temp[LENGTH];
	Big x;

	int lsb1 = G.get(x);
	to_binary(x, LENGTH, buffer, TRUE);
	int lsb2 = tar_partial_public_key.get(x);
	to_binary(x, LENGTH, buffer + LENGTH, TRUE);
	int lsb31 = old_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*2, TRUE);
	int lsb32 = old_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*3, TRUE);
	int lsb41 = new_ciphertext.c1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*4, TRUE);
	int lsb42 = new_ciphertext.c2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*5, TRUE);
	int lsb5 = proof.T1.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*6, TRUE);
	int lsb6 = proof.T2.get(x);
	to_binary(x, LENGTH, buffer + LENGTH*7, TRUE);

	shs256_process(&sh, lsb1);
	shs256_process(&sh, lsb2);
	shs256_process(&sh, lsb31);
	shs256_process(&sh, lsb32);
	shs256_process(&sh, lsb41);
	shs256_process(&sh, lsb42);
	shs256_process(&sh, lsb5);
	shs256_process(&sh, lsb6);
	for (int i = 0; i < LENGTH*8; i++) {
		shs256_process(&sh, buffer[i]);
	}
	shs256_hash(&sh, temp);

	Big delta = from_binary(LENGTH, temp);

	ECn left1 = proof.eta*old_ciphertext.c1;
	ECn left2 = proof.eta*G;

	ECn right1 = old_ciphertext.c2;
	right1 -= new_ciphertext.c2;
	right1 *= delta;
	right1 += proof.T1;

	ECn right2 = delta*tar_partial_public_key;
	right2 += proof.T2;

	if ((old_ciphertext.c1 == new_ciphertext.c1) &&
		(left1 == right1) && (left2 == right2))
		return true;
	else return false;
}


/*
	ZK shuffle proofs

	Warning: we do NOT really implement the permutation operation Pi
	for parallel computation concern. We hold the view that permutation
	will NOT significantly affect the performance. To really implement the
	permutation Pi, please modify the function "Pi(unsigned int i)" as well
	as "Pi_inv(unsigned int i)" above this .cpp file.
*/
void ElGamal::ZK_Shuffle_Prove_Stage_1(ZK_Shuffle_Prover_Context& context,
	const vector<Big>& vec_beta,
	const vector<ElGamalCiphertext>& vec_new_ciphertext,
	const vector<ElGamalCiphertext>& vec_old_ciphertext) {

	cout << "  Prover k = " << context.k << endl;

	if ((context.k != vec_old_ciphertext.size()) || 
		(context.k != vec_new_ciphertext.size())) {
		cout << "[!] Fatal error in ZK_Shuffle_Prove_Stage_1(...): size does not match!" << endl;
		throw;
	}

	context.tau0 = rand(q);
	context.v = rand(q);
	context.gamma = rand(q);

	context.vec_u.resize(context.k);
	context.vec_w.resize(context.k);
	context.vec_a.resize(context.k);

	// Randomize vector u, w, a
	// There is no duplicated element in vector a
	for (int i = 0; i < context.k; i++) {
		context.vec_u[i] = rand(q);
		context.vec_w[i] = rand(q);
		context.vec_a[i] = rand(q);
		/*
		bool flag = true;
		while (flag) {
			for (int j = 0; j < i; j++) {
				if (context.vec_a[i] == context.vec_a[j]) {	// If duplicated
					context.vec_a[i] = rand(q);
					cout << "  duplicated in j = " << j << endl;
					break;
				}
				else {
					flag = false;
					cout << "  check point 1" << endl;
					break;
				}
			}
		}
		*/
	}

	context.stage_1_proof.Gamma = context.gamma*G;
	
	context.stage_1_proof.A.resize(context.k);
	context.stage_1_proof.C.resize(context.k);
	context.stage_1_proof.U.resize(context.k);
	context.stage_1_proof.W.resize(context.k);
	for (int i = 0; i < context.k; i++) {
		context.stage_1_proof.A[i] = context.vec_a[i]*G;
	}
	for (int i = 0; i < context.k; i++) {
		context.stage_1_proof.C[i] = context.gamma*context.stage_1_proof.A[Pi(i)];
		context.stage_1_proof.U[i] = context.vec_u[i]*G;
		context.stage_1_proof.W[i] = (context.gamma*context.vec_w[i])*G;
	}

	context.stage_1_proof.Lambda1 = context.tau0*G;
	for (int i = 0; i < context.k; i++) {
		context.stage_1_proof.Lambda1 += (context.vec_w[i]*vec_beta[Pi(i)])*G;
		context.stage_1_proof.Lambda1 += 
			(context.vec_w[Pi_inv(i)] - context.vec_u[i])*vec_old_ciphertext[i].c1;
	}
	context.stage_1_proof.Lambda2 = context.tau0*global_public_key;
	for (int i = 0; i < context.k; i++) {
		context.stage_1_proof.Lambda2 += (context.vec_w[i]*vec_beta[Pi(i)])*global_public_key;
		context.stage_1_proof.Lambda2 += 
			(context.vec_w[Pi_inv(i)] - context.vec_u[i])*vec_old_ciphertext[i].c2;
	}

	cout << "  ZK_Shuffle_Prove_Stage_1 end" << endl;
}

void ElGamal::ZK_Shuffle_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
	const ZK_Shuffle_Stage_1_Proof& stage_1_proof) {

	context.stage_1_proof = stage_1_proof;
	cout << "  Verifier k = " << context.k << endl;

	context.B.resize(context.k);
	context.stage_1_challenge.vec_rho.resize(context.k);
	for (int i = 0; i < context.k; i++) {
		context.stage_1_challenge.vec_rho[i] = rand(q);
		context.B[i] = context.stage_1_challenge.vec_rho[i]*G;
		context.B[i] -= context.stage_1_proof.U[i];
	}

	cout << "  ZK_Shuffle_Verify_Stage_1 end" << endl;
}

void ElGamal::ZK_Shuffle_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
	const ZK_Shuffle_Stage_1_Challenge& stage_1_challenge) {

	context.vec_b.resize(context.k);
	context.vec_d.resize(context.k);
	context.stage_2_proof.D.resize(context.k);

	for (int i = 0; i < context.k; i++) {
		context.vec_b[i] = stage_1_challenge.vec_rho[i] - context.vec_u[i];
	}

	for (int i = 0; i < context.k; i++) {
		context.vec_d[i] = context.gamma*context.vec_b[Pi(i)];
		context.stage_2_proof.D[i] = (context.gamma*context.vec_b[Pi(i)])*G;
	}

	cout << "  ZK_Shuffle_Prove_Stage_2 end" << endl;
}

void ElGamal::ZK_Shuffle_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
	const ZK_Shuffle_Stage_2_Proof& stage_2_proof) {

	context.stage_2_proof = stage_2_proof;
	context.lambda = rand(q);

	cout << "  ZK_Shuffle_Verify_Stage_2 end" << endl;
}

void ElGamal::ZK_Shuffle_Prove_Stage_3(ZK_Shuffle_Prover_Context& context,
	const vector<Big>& vec_beta, const Big& lambda) {

	context.vec_r.resize(context.k);
	context.vec_s.resize(context.k);

	context.stage_3_proof.vec_sigma.resize(context.k);
	for (int i = 0; i < context.k; i++) {
		context.vec_r[i] = context.vec_a[i] + lambda*context.vec_b[i];
		context.vec_r[i] %= q;
		if (context.vec_r[i] < 0)
			context.vec_r[i] += q;
	}
	for (int i = 0; i < context.k; i++) {
		context.vec_s[i] = context.gamma*context.vec_r[Pi(i)];
		context.vec_s[i] %= q;
		if (context.vec_s[i] < 0)
			context.vec_s[i] += q;

		context.stage_3_proof.vec_sigma[i] = 
			context.vec_w[i] + inverse(context.gamma, q)*context.vec_d[i];
		context.stage_3_proof.vec_sigma[i] %= q;
		if (context.stage_3_proof.vec_sigma[i] < 0)
			context.stage_3_proof.vec_sigma[i] += q;
	}
	context.stage_3_proof.tau = 0;
	for (int i = 0; i < context.k; i++) {
		context.stage_3_proof.tau += context.vec_b[i]*vec_beta[i];
		context.stage_3_proof.tau %= q;
	}
	context.stage_3_proof.tau -= context.tau0;
	context.stage_3_proof.tau %= q;
	if (context.stage_3_proof.tau < 0)
		context.stage_3_proof.tau += q;

	cout << "  ZK_Shuffle_Prove_Stage_3 end" << endl;
}

void ElGamal::ZK_Shuffle_Verify_Stage_3(ZK_Shuffle_Verifier_Context& context,
	const ZK_Shuffle_Stage_3_Proof stage_3_proof) {

	context.stage_3_proof = stage_3_proof;

	context.R.resize(context.k);
	context.S.resize(context.k);

	for (int i = 0; i < context.k; i++) {
		context.R[i] = context.stage_1_proof.A[i];
		context.R[i] += context.lambda*context.B[i];

		context.S[i] = context.stage_1_proof.C[i];
		context.S[i] += context.lambda*context.stage_2_proof.D[i];
	}

	context.t = rand(q);

	cout << "  ZK_Shuffle_Verify_Stage_3 end" << endl;
}

/*
	ZK simple k-shuffle proofs (used as subroutines of ZK shuffle proofs)

	Warning: These routines should be called ONLY after finishing the above
	stages. Or else the contexts of prover and verifier will be incorrect.
	Can NOT be reused independently.
*/
void ElGamal::ZK_SS_Prove_Stage_1(ZK_Shuffle_Prover_Context& context,
	const Big& t) {

	for (int i = 0; i < context.k; i++) {
		context.vec_r[i] -= t;
		context.vec_r[i] %= q;
		if (context.vec_r[i] < 0)
			context.vec_r[i] += q;

		context.vec_s[i] -= context.gamma*t;
		context.vec_s[i] %= q;
		if (context.vec_s[i] < 0)
			context.vec_s[i] += q;
	}

	context.vec_theta.resize(2*context.k - 1);
	for (int i = 0; i < 2*context.k - 1; i++) {
		context.vec_theta[i] = rand(q);
	}

	context.ss_stage_1_proof.Theta.resize(2*context.k);

	context.ss_stage_1_proof.Theta[0] = 0*G;
	context.ss_stage_1_proof.Theta[0] -=
		(context.vec_theta[0]*context.vec_s[0])*G;

	for (int i = 1; i <= context.k - 1; i++) {
		context.ss_stage_1_proof.Theta[i] = 
			(context.vec_theta[i-1]*context.vec_r[i] - context.vec_theta[i]*context.vec_s[i])*G;
	}

	for (int i = context.k; i <= 2*context.k - 2; i++) {
		context.ss_stage_1_proof.Theta[i] = 
			((context.gamma*context.vec_theta[i-1] - context.vec_theta[i])%q)*G;
	}

	context.ss_stage_1_proof.Theta[2*context.k-1] =
		(context.gamma*context.vec_theta[2*context.k-2])*G;

	cout << "    ZK_SS_Prove_Stage_1 end" << endl;
}

void ElGamal::ZK_SS_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
	const ZK_SS_Stage_1_Proof& ss_stage_1_proof) {

	context.ss_stage_1_proof = ss_stage_1_proof;
	context.c = rand(q);

	cout << "    ZK_SS_Verify_Stage_1 end" << endl;
}

void ElGamal::ZK_SS_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
	const Big& c) {

	context.ss_stage_2_proof.alpha.resize(2*context.k - 1);

	for (int i = 0; i <= context.k - 1; i++) {
		Big temp = 1;
		for (int j = 0; j <= i; j++) {
			temp *= ((context.vec_r[j]*inverse(context.vec_s[j], q))%q);
			temp %= q;
		}
		context.ss_stage_2_proof.alpha[i] = 
			((context.vec_theta[i] + c*temp)%q);
	}

	Big gamma_inv = inverse(context.gamma, q);

	for (int i = context.k; i <= 2*context.k - 2; i++) {
		context.ss_stage_2_proof.alpha[i] = 
			context.vec_theta[i] + c*pow(gamma_inv, 2*context.k - 1 - i, q);
		context.ss_stage_2_proof.alpha[i] %= q;
	}

	cout << "    ZK_SS_Prove_Stage_2 end" << endl;
}

bool ElGamal::ZK_SS_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
	const ZK_SS_Stage_2_Proof& ss_stage_2_proof) {

	context.t.negate();

	ECn U = context.t*G;
	ECn W = context.t*context.stage_1_proof.Gamma;

	for (int i = 0; i <= context.k - 1; i++) {
		context.R[i] += U;
		context.S[i] += W;
	}

	ECn left;
	
	left = context.c*context.R[0];
	left -= ss_stage_2_proof.alpha[0]*context.S[0];
	if (left != context.ss_stage_1_proof.Theta[0]) return false;

	for (int i = 1; i <= context.k - 1; i++) {
		left = ss_stage_2_proof.alpha[i-1]*context.R[i];
		left -= ss_stage_2_proof.alpha[i]*context.S[i];

		if (left != context.ss_stage_1_proof.Theta[i]) return false;
	}

	for (int i = context.k; i <= 2*context.k - 2; i++) {
		left = ss_stage_2_proof.alpha[i-1]*context.stage_1_proof.Gamma;
		left -= ss_stage_2_proof.alpha[i]*G;

		if (left != context.ss_stage_1_proof.Theta[i]) return false;
	}
	
	left = ss_stage_2_proof.alpha[2*context.k-2]*context.stage_1_proof.Gamma;
	left -= context.c*G;
	if (left != context.ss_stage_1_proof.Theta[2*context.k-1]) return false;
	
	cout << "    ZK_SS_Verify_Stage_2 OK ..." << endl;
	return true;
}

bool ElGamal::ZK_Shuffle_Verify_Final(ZK_Shuffle_Verifier_Context& context,
	const vector<ElGamalCiphertext>& vec_new_ciphertext,
	const vector<ElGamalCiphertext>& vec_old_ciphertext) {

	ECn Phi1 = 0*G;
	ECn Phi2 = 0*G;

	for (int i = 0; i < context.k; i++) {
		Phi1 += context.stage_3_proof.vec_sigma[i]*vec_new_ciphertext[i].c1;
		Phi1 -= context.stage_1_challenge.vec_rho[i]*vec_old_ciphertext[i].c1;

		Phi2 += context.stage_3_proof.vec_sigma[i]*vec_new_ciphertext[i].c2;
		Phi2 -= context.stage_1_challenge.vec_rho[i]*vec_old_ciphertext[i].c2;
	}

	ECn left;
	ECn right;
	for (int i = 0; i < context.k; i++) {
		left = context.stage_3_proof.vec_sigma[i]*context.stage_1_proof.Gamma;
		right = context.stage_1_proof.W[i];
		right += context.stage_2_proof.D[i];

		if (left != right) return false;
	}

	left = context.stage_1_proof.Lambda1;
	left += context.stage_3_proof.tau*G;
	if (left != Phi1) return false;

	left = context.stage_1_proof.Lambda2;
	left += context.stage_3_proof.tau*global_public_key;
	if (left != Phi2) return false;

	cout << "  ZK_Shuffle_Verify_Final OK ..." << endl;
	return true;
}




/*
	Some low-level pack/unpack utils
*/
void pack(Big& val, octetStream& o) {
	char buffer[LENGTH];
	unsigned char _buffer[LENGTH];
	to_binary(val, LENGTH, buffer, TRUE);
	memcpy(_buffer, buffer, LENGTH);
	o.append(_buffer, LENGTH);
}

void pack(ECn& point, octetStream& o) {
	Big x, y;
	if (point.get_status() != MR_EPOINT_INFINITY)
		point.get(x, y);
	else {
		x = 0;
		y = 0;
	}
	pack(x, o);
	pack(y, o);
}

void unpack(Big& val, octetStream& o) {
	char buffer[LENGTH];
	unsigned char _buffer[LENGTH];
	o.consume(_buffer, LENGTH);
	memcpy(buffer, _buffer, LENGTH);
	val = from_binary(LENGTH, buffer);
}

void unpack(ECn& point, octetStream& o) {
	Big x, y;
	unpack(x, o);
	unpack(y, o);
	if (x == 0 && y == 0)
		(point.get_point())->marker = MR_EPOINT_INFINITY;
	else
		point.set(x, y);
}
