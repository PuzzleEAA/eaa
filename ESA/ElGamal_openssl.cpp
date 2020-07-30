#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#include "ElGamal_openssl.h"

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




void ElGamal::init_key_pair(bool print) {

	cout << "[*] Generating new key pair ..." << endl;

	BN_rand_range(partial_secret_key, q);
	EC_POINT_mul(curve, partial_public_key, NULL,
		G, partial_secret_key, ctx);

	global_public_key = EC_POINT_dup(partial_public_key, curve);
}

void ElGamal::add_other_public_key(const EC_POINT *other_public_key,
	const unsigned int party_id) {

	other_public_keys[party_id] = EC_POINT_dup(other_public_key, curve);
	EC_POINT_add(curve, global_public_key,
		global_public_key, other_public_key, ctx);
}


/*
	ElGamal scheme (distributed decryption ver.)
*/
void ElGamal::encrypt(ElGamalCiphertext& ciphertext,
	const EC_POINT *M, BIGNUM *r) {

	BN_rand_range(r, q);

	EC_POINT_mul(curve, ciphertext.c1, NULL,
		G, r, ctx);
	EC_POINT_mul(curve, ciphertext.c2, NULL,
		global_public_key, r, ctx);
	EC_POINT_add(curve, ciphertext.c2,
		ciphertext.c2, M, ctx);
}

void ElGamal::partial_decrypt(ElGamalCiphertext& new_ciphertext,
	ElGamalCiphertext& old_ciphertext) {

	EC_POINT_copy(new_ciphertext.c1, old_ciphertext.c1);
	EC_POINT_copy(new_ciphertext.c2, old_ciphertext.c2);

	EC_POINT *temp = EC_POINT_new(curve);
	EC_POINT_mul(curve, temp, NULL,
		old_ciphertext.c1, partial_secret_key, ctx);
	EC_POINT_invert(curve, temp, ctx);

	EC_POINT_add(curve, new_ciphertext.c2,
		new_ciphertext.c2, temp, ctx);

	EC_POINT_free(temp);
}

void ElGamal::re_encrypt(ElGamalCiphertext& new_ciphertext,
	ElGamalCiphertext& old_ciphertext, BIGNUM *r) {

	BN_rand_range(r, q);

	EC_POINT_copy(new_ciphertext.c1, old_ciphertext.c1);
	EC_POINT_copy(new_ciphertext.c2, old_ciphertext.c2);

	EC_POINT *temp1 = EC_POINT_new(curve);
	EC_POINT *temp2 = EC_POINT_new(curve);

	EC_POINT_mul(curve, temp1, NULL,
		G, r, ctx);
	EC_POINT_mul(curve, temp2, NULL,
		global_public_key, r, ctx);

	EC_POINT_add(curve, new_ciphertext.c1,
		new_ciphertext.c1, temp1, ctx);
	EC_POINT_add(curve, new_ciphertext.c2,
		new_ciphertext.c2, temp2, ctx);

	EC_POINT_free(temp1);
	EC_POINT_free(temp2);
}

void ElGamal::randomize(ElGamalCiphertext& new_ciphertext,
	ElGamalCiphertext& old_ciphertext, BIGNUM *r) {

	BN_rand_range(r, q);

	EC_POINT_mul(curve, new_ciphertext.c1, NULL,
		old_ciphertext.c1, r, ctx);
	EC_POINT_mul(curve, new_ciphertext.c2, NULL,
		old_ciphertext.c2, r, ctx);
}


/*
	NIZKs
*/
void ElGamal::NIZK_DL_Prove(NIZK_DL_Proof& proof,
	BIGNUM *secret, EC_POINT *exp_secret) {

	BIGNUM *gamma = BN_new();
	BN_rand_range(gamma, q);
	EC_POINT_mul(curve, proof.T, NULL,
		G, gamma, ctx);

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, exp_secret, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);
	BN_bin2bn(hash, LENGTH, proof.eta);
	BN_mod_mul(proof.eta, proof.eta, secret, q, ctx);
	BN_mod_add(proof.eta, proof.eta, gamma, q, ctx);

	BN_free(gamma);
	BN_free(x);
	BN_free(y);
}

bool ElGamal::NIZK_DL_Verify(NIZK_DL_Proof& proof, 
	const EC_POINT *tar_partial_public_key) {

	EC_POINT *left = EC_POINT_new(curve);
	EC_POINT_mul(curve, left, NULL,
		G, proof.eta, ctx);

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, tar_partial_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	BIGNUM *delta = BN_new();
	SHA256_Final(hash, &sha_ctx);
	BN_bin2bn(hash, LENGTH, delta);

	EC_POINT *right = EC_POINT_new(curve);
	EC_POINT_mul(curve, right, NULL,
		tar_partial_public_key, delta, ctx);
	EC_POINT_add(curve, right,
		right, proof.T, ctx);

	if (EC_POINT_cmp(curve, left, right, ctx) == 0) {
		EC_POINT_free(left);
		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(right);
		return true;
	}
	else {
		EC_POINT_free(left);
		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(right);
		return false;
	}
}

void ElGamal::NIZK_RE_Prove(NIZK_RE_Proof& proof,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext,
	const BIGNUM *r) {

	BIGNUM *gamma = BN_new();
	BN_rand_range(gamma, q);
	EC_POINT_mul(curve, proof.T1, NULL,
		G, gamma, ctx);
	EC_POINT_mul(curve, proof.T2, NULL,
		global_public_key, gamma, ctx);

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, global_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);
	BN_bin2bn(hash, LENGTH, proof.eta);

	BN_mod_mul(proof.eta, proof.eta, r, q, ctx);
	BN_mod_add(proof.eta, proof.eta, gamma, q, ctx);

	BN_free(gamma);
	BN_free(x);
	BN_free(y);
}

bool ElGamal::NIZK_RE_Verify(NIZK_RE_Proof& proof,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext) {

	EC_POINT *left1 = EC_POINT_new(curve);
	EC_POINT *left2 = EC_POINT_new(curve);

	EC_POINT_mul(curve, left1, NULL,
		G, proof.eta, ctx);
	EC_POINT_mul(curve, left2, NULL,
		global_public_key, proof.eta, ctx);

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, global_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	BIGNUM *delta = BN_new();
	SHA256_Final(hash, &sha_ctx);
	BN_bin2bn(hash, LENGTH, delta);

	EC_POINT *right1 = EC_POINT_dup(old_ciphertext.c1, curve);
	EC_POINT_invert(curve, right1, ctx);
	EC_POINT_add(curve, right1,
		right1, new_ciphertext.c1, ctx);
	EC_POINT_mul(curve, right1, NULL,
		right1, delta, ctx);
	EC_POINT_add(curve, right1,
		right1, proof.T1, ctx);

	EC_POINT *right2 = EC_POINT_dup(old_ciphertext.c2, curve);
	EC_POINT_invert(curve, right2, ctx);
	EC_POINT_add(curve, right2,
		right2, new_ciphertext.c2, ctx);
	EC_POINT_mul(curve, right2, NULL,
		right2, delta, ctx);
	EC_POINT_add(curve, right2,
		right2, proof.T2, ctx);

	if ((EC_POINT_cmp(curve, left1, right1, ctx) == 0) &&
		(EC_POINT_cmp(curve, left2, right2, ctx) == 0)) {
		EC_POINT_free(left1);
		EC_POINT_free(left2);
		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(right1);
		EC_POINT_free(right2);
		return true;
	}
	else {
		EC_POINT_free(left1);
		EC_POINT_free(left2);
		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(right1);
		EC_POINT_free(right2);
		return false;
	}
}

void ElGamal::NIZK_OR_Prove(NIZK_OR_Proof& proof,
	const ElGamalCiphertext new_ciphertexts[2], const int b,
	const ElGamalCiphertext& old_ciphertext,
	const BIGNUM *r) {

	BIGNUM *gamma = BN_new();
	BN_rand_range(gamma, q);
	BIGNUM *delta_other = BN_new();
	BN_rand_range(delta_other, q);
	BIGNUM *eta_other = BN_new();
	BN_rand_range(eta_other, q);

	if ((b == 0) || (b == 1)) {
		EC_POINT_mul(curve, proof.T1[b], NULL,
			G, gamma, ctx);
		EC_POINT_mul(curve, proof.T2[b], NULL,
			global_public_key, gamma, ctx);

		EC_POINT_mul(curve, proof.T1[1-b], NULL,
			G, eta_other, ctx);
		EC_POINT *_temp1 = EC_POINT_dup(old_ciphertext.c1, curve);
		EC_POINT_invert(curve, _temp1, ctx);
		EC_POINT_add(curve, _temp1,
			_temp1, new_ciphertexts[1-b].c1, ctx);
		EC_POINT_mul(curve, _temp1, NULL,
			_temp1, delta_other, ctx);
		EC_POINT_invert(curve, _temp1, ctx);
		EC_POINT_add(curve, proof.T1[1-b],
			proof.T1[1-b], _temp1, ctx);

		EC_POINT_mul(curve, proof.T2[1-b], NULL,
			global_public_key, eta_other, ctx);
		EC_POINT *_temp2 = EC_POINT_dup(old_ciphertext.c2, curve);
		EC_POINT_invert(curve, _temp2, ctx);
		EC_POINT_add(curve, _temp2,
			_temp2, new_ciphertexts[1-b].c2, ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			_temp2, delta_other, ctx);
		EC_POINT_invert(curve, _temp2, ctx);
		EC_POINT_add(curve, proof.T2[1-b],
			proof.T2[1-b], _temp2, ctx);

		EC_POINT_free(_temp1);
		EC_POINT_free(_temp2);
	}
	else {
		cout << "[!] Fatal error in NIZK_OR_Prove(...): invalid b = " << b << endl;
		throw;
	}

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, global_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[0].c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[0].c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[1].c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[1].c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1[0], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2[0], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1[1], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2[1], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);

	BN_copy(proof.delta[1-b], delta_other);

	unsigned char temp_other[LENGTH];
	memset(temp_other, 0, LENGTH);
	BN_bn2binpad(delta_other, temp_other, LENGTH);

	// Perform xor operation
	for (int i = 0; i < LENGTH; i++) {
		hash[i] ^= temp_other[i];
	}

	BIGNUM *_temp3 = BN_new();
	BN_bin2bn(hash, LENGTH, _temp3);
	BN_copy(proof.delta[b], _temp3);

	//proof.delta[1-b] = BN_dup(delta_other);

	//proof.eta[b] = BN_dup(proof.delta[b]);
	BN_copy(proof.eta[b], proof.delta[b]);
	BN_mod_mul(proof.eta[b], proof.eta[b], r, q, ctx);
	BN_mod_add(proof.eta[b], proof.eta[b], gamma, q, ctx);
	//proof.eta[1-b] = BN_dup(eta_other);
	BN_copy(proof.eta[1-b], eta_other);

	BN_free(gamma);
	BN_free(delta_other);
	BN_free(eta_other);
	BN_free(x);
	BN_free(y);
	BN_free(_temp3);
}

bool ElGamal::NIZK_OR_Verify(NIZK_OR_Proof& proof,
	const ElGamalCiphertext new_ciphertexts[2],
	const ElGamalCiphertext& old_ciphertext) {

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, global_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[0].c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[0].c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[1].c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertexts[1].c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1[0], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2[0], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1[1], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2[1], x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);
	unsigned char _temp1[LENGTH], _temp2[LENGTH];
	memset(_temp1, 0, LENGTH);
	memset(_temp2, 0, LENGTH);
	BN_bn2binpad(proof.delta[0], _temp1, LENGTH);
	BN_bn2binpad(proof.delta[1], _temp2, LENGTH);

	for (int i = 0; i < LENGTH; i++)
		if (hash[i] != (_temp1[i] ^ _temp2[i]))
			return false;

	EC_POINT *left1[2], *left2[2];
	EC_POINT *right1[2], *right2[2];

	for (int i = 0; i < 2; i++) {
		left1[i] = EC_POINT_new(curve);
		left2[i] = EC_POINT_new(curve);
		right1[i] = EC_POINT_new(curve);
		right2[i] = EC_POINT_new(curve);
	}

	for (int i = 0; i < 2; i++) {
		EC_POINT_mul(curve, left1[i], NULL,
			G, proof.eta[i], ctx);
		EC_POINT_mul(curve, left2[i], NULL,
			global_public_key, proof.eta[i], ctx);

		EC_POINT_copy(right1[i], old_ciphertext.c1);
		EC_POINT_invert(curve, right1[i], ctx);
		EC_POINT_add(curve, right1[i],
			right1[i], new_ciphertexts[i].c1, ctx);
		EC_POINT_mul(curve, right1[i], NULL,
			right1[i], proof.delta[i], ctx);
		EC_POINT_add(curve, right1[i],
			right1[i], proof.T1[i], ctx);

		EC_POINT_copy(right2[i], old_ciphertext.c2);
		EC_POINT_invert(curve, right2[i], ctx);
		EC_POINT_add(curve, right2[i],
			right2[i], new_ciphertexts[i].c2, ctx);
		EC_POINT_mul(curve, right2[i], NULL,
			right2[i], proof.delta[i], ctx);
		EC_POINT_add(curve, right2[i],
			right2[i], proof.T2[i], ctx);
	}

	if ((EC_POINT_cmp(curve, left1[0], right1[0], ctx) == 0) &&
		(EC_POINT_cmp(curve, left2[0], right2[0], ctx) == 0) &&
		(EC_POINT_cmp(curve, left1[1], right1[1], ctx) == 0) &&
		(EC_POINT_cmp(curve, left2[1], right2[1], ctx) == 0))
	{
		BN_free(x);
		BN_free(y);
		for (int i = 0; i < 2; i++) {
			EC_POINT_free(left1[i]);
			EC_POINT_free(left2[i]);
			EC_POINT_free(right1[i]);
			EC_POINT_free(right2[i]);
		}
		return true;
	}
	else {
		BN_free(x);
		BN_free(y);
		for (int i = 0; i < 2; i++) {
			EC_POINT_free(left1[i]);
			EC_POINT_free(left2[i]);
			EC_POINT_free(right1[i]);
			EC_POINT_free(right2[i]);
		}
		return false;
	}
}

void ElGamal::NIZK_S_Prove(NIZK_S_Proof& proof,
	const ElGamalCiphertext new_ciphertexts[2],
	const ElGamalCiphertext old_ciphertexts[2],
	BIGNUM *r[2], const int isShuffled) {

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
	const BIGNUM *re_enc_r, const BIGNUM *rand_r) {

	BIGNUM *gamma1 = BN_new();
	BIGNUM *gamma2 = BN_new();
	EC_POINT *_temp1 = EC_POINT_new(curve);
	EC_POINT *_temp2 = EC_POINT_new(curve);

	BN_rand_range(gamma1, q);
	BN_rand_range(gamma2, q);

	EC_POINT_mul(curve, proof.T1, NULL,
		old_ciphertext.c1, gamma1, ctx);
	EC_POINT_mul(curve, _temp1, NULL,
		G, gamma2, ctx);
	EC_POINT_add(curve, proof.T1,
		proof.T1, _temp1, ctx);

	EC_POINT_mul(curve, proof.T2, NULL,
		old_ciphertext.c2, gamma1, ctx);
	EC_POINT_mul(curve, _temp2, NULL,
		global_public_key, gamma2, ctx);
	EC_POINT_add(curve, proof.T2,
		proof.T2, _temp2, ctx);

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, global_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);
	BN_bin2bn(hash, LENGTH, proof.eta1);
	BN_bin2bn(hash, LENGTH, proof.eta2);

	BN_mod_mul(proof.eta1, proof.eta1, rand_r, q, ctx);
	BN_mod_add(proof.eta1, proof.eta1, gamma1, q, ctx);

	BN_mod_mul(proof.eta2, proof.eta2, rand_r, q, ctx);
	BN_mod_mul(proof.eta2, proof.eta2, re_enc_r, q, ctx);
	BN_mod_add(proof.eta2, proof.eta2, gamma2, q, ctx);

	BN_free(gamma1);
	BN_free(gamma2);
	EC_POINT_free(_temp1);
	EC_POINT_free(_temp2);
	BN_free(x);
	BN_free(y);
}

bool ElGamal::NIZK_RR_Verify(NIZK_RR_Proof& proof,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext) {

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, global_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);

	BIGNUM *delta = BN_new();
	BN_bin2bn(hash, LENGTH, delta);

	EC_POINT *left1 = EC_POINT_new(curve);
	EC_POINT *_temp1 = EC_POINT_new(curve);
	EC_POINT_mul(curve, left1, NULL,
		old_ciphertext.c1, proof.eta1, ctx);
	EC_POINT_mul(curve, _temp1, NULL, 
		G, proof.eta2, ctx);
	EC_POINT_add(curve, left1,
		left1, _temp1, ctx);

	EC_POINT *left2 = EC_POINT_new(curve);
	EC_POINT *_temp2 = EC_POINT_new(curve);
	EC_POINT_mul(curve, left2, NULL,
		old_ciphertext.c2, proof.eta1, ctx);
	EC_POINT_mul(curve, _temp2, NULL,
		global_public_key, proof.eta2, ctx);
	EC_POINT_add(curve, left2,
		left2, _temp2, ctx);

	EC_POINT *right1 = EC_POINT_new(curve);
	EC_POINT_mul(curve, right1, NULL,
		new_ciphertext.c1, delta, ctx);
	EC_POINT_add(curve, right1,
		right1, proof.T1, ctx);

	EC_POINT *right2 = EC_POINT_new(curve);
	EC_POINT_mul(curve, right2, NULL,
		new_ciphertext.c2, delta, ctx);
	EC_POINT_add(curve, right2,
		right2, proof.T2, ctx);

	if ((EC_POINT_cmp(curve, left1, right1, ctx) == 0) &&
		(EC_POINT_cmp(curve, left2, right2, ctx) == 0))
	{
		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(left1);
		EC_POINT_free(_temp1);
		EC_POINT_free(left2);
		EC_POINT_free(_temp2);
		EC_POINT_free(right1);
		EC_POINT_free(right2);
		return true;
	}
	else {

		cout << "cp 0" << endl;
		cout << EC_POINT_cmp(curve, left1, right1, ctx) << endl;
		cout << EC_POINT_cmp(curve, left2, right2, ctx) << endl;

		cout << EC_POINT_is_at_infinity(curve ,left1) << endl;
		cout << EC_POINT_is_at_infinity(curve ,left2) << endl;
		cout << EC_POINT_is_at_infinity(curve ,right1) << endl;
		cout << EC_POINT_is_at_infinity(curve ,right2) << endl;

		ERR_print_errors_fp(stdout);

		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(left1);
		EC_POINT_free(_temp1);
		EC_POINT_free(left2);
		EC_POINT_free(_temp2);
		EC_POINT_free(right1);
		EC_POINT_free(right2);
		return false;
	}
}

void ElGamal::NIZK_DLE_Prove(NIZK_DLE_Proof& proof,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext) {

	BIGNUM *gamma = BN_new();
	BN_rand_range(gamma, q);
	EC_POINT_mul(curve, proof.T1, NULL,
		old_ciphertext.c1, gamma, ctx);
	EC_POINT_mul(curve, proof.T2, NULL,
		G, gamma, ctx);

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, partial_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);
	BN_bin2bn(hash, LENGTH, proof.eta);
	BN_mod_mul(proof.eta, proof.eta, partial_secret_key, q, ctx);
	BN_mod_add(proof.eta, proof.eta, gamma, q, ctx);

	BN_free(gamma);
	BN_free(x);
	BN_free(y);
}

bool ElGamal::NIZK_DLE_Verify(NIZK_DLE_Proof& proof,
	const EC_POINT *tar_partial_public_key,
	const ElGamalCiphertext& new_ciphertext,
	const ElGamalCiphertext& old_ciphertext) {

	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	unsigned char bin_x[LENGTH]; memset(bin_x, 0, LENGTH);
	unsigned char bin_y[LENGTH]; memset(bin_y, 0, LENGTH);
	unsigned char hash[LENGTH];

	EC_POINT_get_affine_coordinates_GFp(curve, G, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, tar_partial_public_key, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, old_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, new_ciphertext.c2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T1, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	EC_POINT_get_affine_coordinates_GFp(curve, proof.T2, x, y, ctx);
	BN_bn2binpad(x, bin_x, LENGTH);
	BN_bn2binpad(y, bin_y, LENGTH);
	SHA256_Update(&sha_ctx, bin_x, LENGTH); memset(bin_x, 0, LENGTH);
	SHA256_Update(&sha_ctx, bin_y, LENGTH); memset(bin_y, 0, LENGTH);

	SHA256_Final(hash, &sha_ctx);
	BIGNUM *delta = BN_new();
	BN_bin2bn(hash, LENGTH, delta);

	EC_POINT *left1 = EC_POINT_new(curve);
	EC_POINT_mul(curve, left1, NULL,
		old_ciphertext.c1, proof.eta, ctx);

	EC_POINT *left2 = EC_POINT_new(curve);
	EC_POINT_mul(curve, left2, NULL,
		G, proof.eta, ctx);

	EC_POINT *right1 = EC_POINT_new(curve);
	EC_POINT_copy(right1, new_ciphertext.c2);
	EC_POINT_invert(curve, right1, ctx);
	EC_POINT_add(curve, right1,
		right1, old_ciphertext.c2, ctx);
	EC_POINT_mul(curve, right1, NULL,
		right1, delta, ctx);
	EC_POINT_add(curve, right1,
		right1, proof.T1, ctx);

	EC_POINT *right2 = EC_POINT_new(curve);
	EC_POINT_mul(curve, right2, NULL,
		tar_partial_public_key, delta, ctx);
	EC_POINT_add(curve, right2,
		right2, proof.T2, ctx);

	if ((EC_POINT_cmp(curve, old_ciphertext.c1, new_ciphertext.c1, ctx) == 0) &&
		(EC_POINT_cmp(curve, left1, right1, ctx) == 0) &&
		(EC_POINT_cmp(curve, left2, right2, ctx) == 0))
	{
		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(left1);
		EC_POINT_free(left2);
		EC_POINT_free(right1);
		EC_POINT_free(right2);
		return true;
	}
	else {
		BN_free(x);
		BN_free(y);
		BN_free(delta);
		EC_POINT_free(left1);
		EC_POINT_free(left2);
		EC_POINT_free(right1);
		EC_POINT_free(right2);
		return false;
	}
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
	const vector<BIGNUM *>& vec_beta,
	const vector<ElGamalCiphertext>& vec_new_ciphertext,
	const vector<ElGamalCiphertext>& vec_old_ciphertext) {

	cout << "      Prover k = " << context.k << endl;

	if ((context.k != vec_old_ciphertext.size()) || 
		(context.k != vec_new_ciphertext.size())) {
		cout << "[!] Fatal error in ZK_Shuffle_Prove_Stage_1(...): size does not match!" << endl;
		throw;
	}

	BN_rand_range(context.tau0, q);
	BN_rand_range(context.v, q);
	BN_rand_range(context.gamma, q);

	// Randomize vector u, w, a
	// There is no duplicated element in vector a
	for (int i = 0; i < context.k; i++) {
		BN_rand_range(context.vec_u[i], q);
		BN_rand_range(context.vec_w[i], q);
		BN_rand_range(context.vec_a[i], q);
		
	}

	EC_POINT_mul(curve, context.stage_1_proof->Gamma, NULL,
		G, context.gamma, ctx);

	for (int i = 0; i < context.k; i++) {
		EC_POINT_mul(curve, context.stage_1_proof->A[i], NULL,
			G, context.vec_a[i], ctx);
	}
	for (int i = 0; i < context.k; i++) {
		EC_POINT_mul(curve, context.stage_1_proof->C[i], NULL,
		 	context.stage_1_proof->A[Pi(i)], context.gamma, ctx);
		EC_POINT_mul(curve, context.stage_1_proof->U[i], NULL,
		 	G, context.vec_u[i], ctx);
		EC_POINT_mul(curve, context.stage_1_proof->W[i], NULL,
		 	G, context.vec_w[i], ctx);
		EC_POINT_mul(curve, context.stage_1_proof->W[i], NULL,
		 	context.stage_1_proof->W[i], context.gamma, ctx);
	}

	BIGNUM *_temp1 = BN_new();
	EC_POINT *_temp2 = EC_POINT_new(curve);
	EC_POINT *_temp3 = EC_POINT_new(curve);

	EC_POINT_mul(curve, context.stage_1_proof->Lambda1, NULL,
		G, context.tau0, ctx);
	for (int i = 0; i < context.k; i++) {
		/*
		BN_mod_mul(_temp1, context.vec_w[i], vec_beta[Pi(i)], q, ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			G, _temp1, ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda1,
			context.stage_1_proof->Lambda1, _temp2, ctx);

		BN_mod_sub(_temp1, context.vec_w[Pi_inv(i)], context.vec_u[i], q, ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			vec_old_ciphertext[i].c1, _temp1, ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda1,
			context.stage_1_proof->Lambda1, _temp2, ctx);
		*/
		EC_POINT_mul(curve, _temp2, NULL,
			G, vec_beta[Pi(i)], ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			_temp2, context.vec_w[i], ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda1,
			context.stage_1_proof->Lambda1, _temp2, ctx);

		EC_POINT_mul(curve, _temp2, NULL,
			vec_old_ciphertext[i].c1, context.vec_u[i], ctx);
		EC_POINT_invert(curve, _temp2, ctx);
		EC_POINT_mul(curve, _temp3, NULL,
			vec_old_ciphertext[i].c1, context.vec_w[Pi_inv(i)], ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda1,
			context.stage_1_proof->Lambda1, _temp2, ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda1,
			context.stage_1_proof->Lambda1, _temp3, ctx);
	}

	EC_POINT_mul(curve, context.stage_1_proof->Lambda2, NULL,
	 	global_public_key, context.tau0, ctx);
	for (int i = 0; i < context.k; i++) {
		/*
		BN_mod_mul(_temp1, context.vec_w[i], vec_beta[Pi(i)], q, ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			global_public_key, _temp1, ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda2,
			context.stage_1_proof->Lambda2, _temp2, ctx);

		BN_mod_sub(_temp1, context.vec_w[Pi_inv(i)], context.vec_u[i], q, ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			vec_old_ciphertext[i].c2, _temp1, ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda2,
			context.stage_1_proof->Lambda2, _temp2, ctx);
		*/
		EC_POINT_mul(curve, _temp2, NULL,
			global_public_key, vec_beta[Pi(i)], ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			_temp2, context.vec_w[i], ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda2,
			context.stage_1_proof->Lambda2, _temp2, ctx);

		EC_POINT_mul(curve, _temp2, NULL,
			vec_old_ciphertext[i].c2, context.vec_u[i], ctx);
		EC_POINT_invert(curve, _temp2, ctx);
		EC_POINT_mul(curve, _temp3, NULL,
			vec_old_ciphertext[i].c2, context.vec_w[Pi_inv(i)], ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda2,
			context.stage_1_proof->Lambda2, _temp2, ctx);
		EC_POINT_add(curve, context.stage_1_proof->Lambda2,
			context.stage_1_proof->Lambda2, _temp3, ctx);
	}

	BN_free(_temp1);
	EC_POINT_free(_temp2);
	EC_POINT_free(_temp3);
}

void ElGamal::ZK_Shuffle_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
	ZK_Shuffle_Stage_1_Proof *stage_1_proof) {

	context.stage_1_proof = stage_1_proof;
	cout << "      Verifier k = " << context.k << endl;

	EC_POINT *_temp1 = EC_POINT_new(curve);
	for (int i = 0; i < context.k; i++) {
		BN_rand_range(context.stage_1_challenge->vec_rho[i], q);
		EC_POINT_copy(context.B[i], context.stage_1_proof->U[i]);
		EC_POINT_invert(curve, context.B[i], ctx);
		EC_POINT_mul(curve, _temp1, NULL,
			G, context.stage_1_challenge->vec_rho[i], ctx);
		EC_POINT_add(curve, context.B[i],
			context.B[i], _temp1, ctx);
	}

	EC_POINT_free(_temp1);
}

void ElGamal::ZK_Shuffle_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
	ZK_Shuffle_Stage_1_Challenge *stage_1_challenge) {

	for (int i = 0; i < context.k; i++) {
		BN_mod_sub(context.vec_b[i],
			stage_1_challenge->vec_rho[i], context.vec_u[i], q, ctx);
	}

	for (int i = 0; i < context.k; i++) {
		BN_mod_mul(context.vec_d[i],
			context.gamma, context.vec_b[Pi(i)], q, ctx);
		EC_POINT_mul(curve, context.stage_2_proof->D[i], NULL,
			G, context.vec_d[i], ctx);
	}
}

void ElGamal::ZK_Shuffle_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
	ZK_Shuffle_Stage_2_Proof *stage_2_proof) {

	context.stage_2_proof = stage_2_proof;
	BN_rand_range(context.lambda, q);
}

void ElGamal::ZK_Shuffle_Prove_Stage_3(ZK_Shuffle_Prover_Context& context,
	const vector<BIGNUM *>& vec_beta, const BIGNUM *lambda) {

	BIGNUM *zero = BN_new();
	BN_zero(zero);
	
	for (int i = 0; i < context.k; i++) {
		BN_mod_mul(context.vec_r[i],
			lambda, context.vec_b[i], q, ctx);
		BN_mod_add(context.vec_r[i],
			context.vec_r[i], context.vec_a[i], q, ctx);
	}
	for (int i = 0; i < context.k; i++) {
		BN_mod_mul(context.vec_s[i],
			context.gamma, context.vec_r[Pi(i)], q, ctx);

		BN_mod_inverse(context.stage_3_proof->vec_sigma[i],
			context.gamma, q, ctx);
		BN_mod_mul(context.stage_3_proof->vec_sigma[i],
			context.stage_3_proof->vec_sigma[i], context.vec_d[i], q, ctx);
		BN_mod_add(context.stage_3_proof->vec_sigma[i],
			context.stage_3_proof->vec_sigma[i], context.vec_w[i], q, ctx);
	}

	BN_copy(context.stage_3_proof->tau, zero);
	BIGNUM *_temp1 = BN_new();
	for (int i = 0; i < context.k; i++) {
		BN_mod_mul(_temp1, context.vec_b[i], vec_beta[i], q, ctx);
		BN_mod_add(context.stage_3_proof->tau, 
			context.stage_3_proof->tau, _temp1, q, ctx);
	}
	BN_mod_sub(context.stage_3_proof->tau,
		context.stage_3_proof->tau, context.tau0, q, ctx);

	BN_free(zero);
}

void ElGamal::ZK_Shuffle_Verify_Stage_3(ZK_Shuffle_Verifier_Context& context,
	ZK_Shuffle_Stage_3_Proof *stage_3_proof) {

	context.stage_3_proof = stage_3_proof;

	for (int i = 0; i < context.k; i++) {
		EC_POINT_mul(curve, context.R[i], NULL,
			context.B[i], context.lambda, ctx);
		EC_POINT_add(curve, context.R[i],
			context.R[i], context.stage_1_proof->A[i], ctx);

		EC_POINT_mul(curve, context.S[i], NULL,
			context.stage_2_proof->D[i], context.lambda, ctx);
		EC_POINT_add(curve, context.S[i],
			context.S[i], context.stage_1_proof->C[i], ctx);
	}

	BN_rand_range(context.t, q);
}

/*
	ZK simple k-shuffle proofs (used as subroutines of ZK shuffle proofs)

	Warning: These routines should be called ONLY after finishing the above
	stages. Or else the contexts of prover and verifier will be incorrect.
	Can NOT be reused independently.
*/
void ElGamal::ZK_SS_Prove_Stage_1(ZK_Shuffle_Prover_Context& context,
	const BIGNUM *t) {

	BIGNUM *_temp1 = BN_new();

	for (int i = 0; i < context.k; i++) {
		BN_mod_sub(context.vec_r[i],
			context.vec_r[i], t, q, ctx);

		BN_mod_mul(_temp1, context.gamma, t, q, ctx);
		BN_mod_sub(context.vec_s[i],
			context.vec_s[i], _temp1, q, ctx);
	}

	for (int i = 0; i < 2*context.k - 1; i++) {
		BN_rand_range(context.vec_theta[i], q);
	}

	BN_mod_mul(_temp1, context.vec_theta[0], context.vec_s[0], q, ctx);
	EC_POINT_mul(curve, context.ss_stage_1_proof->Theta[0], NULL,
		G, _temp1, ctx);
	EC_POINT_invert(curve, context.ss_stage_1_proof->Theta[0], ctx);

	BIGNUM *_temp2 = BN_new();

	for (int i = 1; i <= context.k - 1; i++) {
		BN_mod_mul(_temp1, context.vec_theta[i-1], context.vec_r[i], q, ctx);
		BN_mod_mul(_temp2, context.vec_theta[i], context.vec_s[i], q, ctx);
		BN_mod_sub(_temp1, _temp1, _temp2, q, ctx);
		EC_POINT_mul(curve, context.ss_stage_1_proof->Theta[i], NULL,
			G, _temp1, ctx);
	}

	for (int i = context.k; i <= 2*context.k - 2; i++) {
		BN_mod_mul(_temp1, context.gamma, context.vec_theta[i-1], q, ctx);
		BN_mod_sub(_temp1, _temp1, context.vec_theta[i], q, ctx);
		EC_POINT_mul(curve, context.ss_stage_1_proof->Theta[i], NULL,
			G, _temp1, ctx);
	}

	BN_mod_mul(_temp1, context.gamma, context.vec_theta[2*context.k-2], q, ctx);
	EC_POINT_mul(curve, context.ss_stage_1_proof->Theta[2*context.k-1], NULL,
		G, _temp1, ctx);

	BN_free(_temp1);
	BN_free(_temp2);
}

void ElGamal::ZK_SS_Verify_Stage_1(ZK_Shuffle_Verifier_Context& context,
	ZK_SS_Stage_1_Proof *ss_stage_1_proof) {

	context.ss_stage_1_proof = ss_stage_1_proof;
	BN_rand_range(context.c, q);
}

void ElGamal::ZK_SS_Prove_Stage_2(ZK_Shuffle_Prover_Context& context,
	const BIGNUM *c) {

	BIGNUM *_temp1 = BN_new();
	BIGNUM *_temp2 = BN_new();
	vector<BIGNUM *> invs;
	vector<BIGNUM *> temps;
	invs.resize(context.k);
	temps.resize(context.k);

	// Pre-computation
	for (int i = 0; i < context.k; i++) {
		invs[i] = BN_new();
		temps[i] = BN_new();
		BN_mod_inverse(invs[i], context.vec_s[i], q, ctx);
		BN_mod_mul(temps[i], invs[i], context.vec_r[i], q, ctx);
	}

	for (int i = 0; i <= context.k - 1; i++) {
		BN_one(_temp1);
		for (int j = 0; j <= i; j++) {
			//BN_mod_inverse(_temp2, context.vec_s[j], q, ctx);
			//BN_mod_mul(_temp2, invs[j], context.vec_r[j], q, ctx);
			BN_mod_mul(_temp1, _temp1, temps[j], q, ctx);
		}
		BN_mod_mul(_temp1, _temp1, c, q, ctx);
		BN_mod_add(context.ss_stage_2_proof->alpha[i],
			context.vec_theta[i], _temp1, q, ctx);
	}

	BN_mod_inverse(_temp1, context.gamma, q, ctx);
	BIGNUM *exp = BN_new();

	for (int i = context.k; i <= 2*context.k - 2; i++) {
		BN_set_word(exp, 2*context.k - 1 - i);
		BN_mod_exp(_temp2, _temp1, exp, q, ctx);
		BN_mod_mul(_temp2, _temp2, c, q, ctx);
		BN_mod_add(context.ss_stage_2_proof->alpha[i],
			context.vec_theta[i], _temp2, q, ctx);
	}

	BN_free(_temp1);
	BN_free(_temp2);
	BN_free(exp);

	for (int i = 0; i < context.k; ++i) {
		BN_free(invs[i]);
		BN_free(temps[i]);
	}
}

bool ElGamal::ZK_SS_Verify_Stage_2(ZK_Shuffle_Verifier_Context& context,
	ZK_SS_Stage_2_Proof *ss_stage_2_proof) {

	EC_POINT *U = EC_POINT_new(curve);
	EC_POINT_mul(curve, U, NULL,
		G, context.t, ctx);
	EC_POINT_invert(curve, U, ctx);

	EC_POINT *W = EC_POINT_new(curve);
	EC_POINT_mul(curve, W, NULL,
		context.stage_1_proof->Gamma, context.t, ctx);
	EC_POINT_invert(curve, W, ctx);

	for (int i = 0; i <= context.k - 1; i++) {
		EC_POINT_add(curve, context.R[i],
			context.R[i], U, ctx);
		EC_POINT_add(curve, context.S[i],
			context.S[i], W, ctx);
	}

	EC_POINT *left = EC_POINT_new(curve);
	EC_POINT *_temp1 = EC_POINT_new(curve);

	EC_POINT_mul(curve, left, NULL,
		context.R[0], context.c, ctx);
	EC_POINT_mul(curve, _temp1, NULL,
		context.S[0], ss_stage_2_proof->alpha[0], ctx);
	EC_POINT_invert(curve, _temp1, ctx);
	EC_POINT_add(curve, left, left, _temp1, ctx);
	if (EC_POINT_cmp(curve, left, context.ss_stage_1_proof->Theta[0], ctx) != 0) {
		EC_POINT_free(U);
		EC_POINT_free(W);
		EC_POINT_free(left);
		EC_POINT_free(_temp1);
		return false;
	}

	for (int i = 1; i <= context.k - 1; i++) {
		EC_POINT_mul(curve, left, NULL,
			context.R[i], ss_stage_2_proof->alpha[i-1], ctx);
		EC_POINT_mul(curve, _temp1, NULL,
			context.S[i], ss_stage_2_proof->alpha[i], ctx);
		EC_POINT_invert(curve, _temp1, ctx);
		EC_POINT_add(curve, left, left, _temp1, ctx);
		if (EC_POINT_cmp(curve, left, context.ss_stage_1_proof->Theta[i], ctx) != 0) {
			EC_POINT_free(U);
			EC_POINT_free(W);
			EC_POINT_free(left);
			EC_POINT_free(_temp1);
			cout << i << endl;
			return false;
		}
	}

	for (int i = context.k; i <= 2*context.k - 2; i++) {
		EC_POINT_mul(curve, left, NULL,
			context.stage_1_proof->Gamma, ss_stage_2_proof->alpha[i-1], ctx);
		EC_POINT_mul(curve, _temp1, NULL,
			G, ss_stage_2_proof->alpha[i], ctx);
		EC_POINT_invert(curve, _temp1, ctx);
		EC_POINT_add(curve, left,
			left, _temp1, ctx);
		if (EC_POINT_cmp(curve, left, context.ss_stage_1_proof->Theta[i], ctx) != 0) {
			EC_POINT_free(U);
			EC_POINT_free(W);
			EC_POINT_free(left);
			EC_POINT_free(_temp1);
			return false;
		}
	}

	EC_POINT_mul(curve, left, NULL,
		context.stage_1_proof->Gamma, ss_stage_2_proof->alpha[2*context.k-2], ctx);
	EC_POINT_mul(curve, _temp1, NULL,
		G, context.c, ctx);
	EC_POINT_invert(curve, _temp1, ctx);
	EC_POINT_add(curve, left,
		left, _temp1, ctx);
	if (EC_POINT_cmp(curve, left, context.ss_stage_1_proof->Theta[2*context.k-1], ctx) != 0) {
		EC_POINT_free(U);
		EC_POINT_free(W);
		EC_POINT_free(left);
		EC_POINT_free(_temp1);
		return false;
	}

	EC_POINT_free(U);
	EC_POINT_free(W);
	EC_POINT_free(left);
	EC_POINT_free(_temp1);

	return true;
}

bool ElGamal::ZK_Shuffle_Verify_Final(ZK_Shuffle_Verifier_Context& context,
	const vector<ElGamalCiphertext>& vec_new_ciphertext,
	const vector<ElGamalCiphertext>& vec_old_ciphertext) {

	EC_POINT *Phi1 = EC_POINT_new(curve);
	EC_POINT *Phi2 = EC_POINT_new(curve);
	EC_POINT_set_to_infinity(curve, Phi1);
	EC_POINT_set_to_infinity(curve, Phi2);

	EC_POINT *_temp1 = EC_POINT_new(curve);
	EC_POINT *_temp2 = EC_POINT_new(curve);

	for (int i = 0; i < context.k; i++) {
		EC_POINT_mul(curve, _temp1, NULL,
			vec_new_ciphertext[i].c1, context.stage_3_proof->vec_sigma[i], ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			vec_old_ciphertext[i].c1, context.stage_1_challenge->vec_rho[i], ctx);
		EC_POINT_invert(curve, _temp2, ctx);
		EC_POINT_add(curve, Phi1, Phi1, _temp1, ctx);
		EC_POINT_add(curve, Phi1, Phi1, _temp2, ctx);

		EC_POINT_mul(curve, _temp1, NULL,
			vec_new_ciphertext[i].c2, context.stage_3_proof->vec_sigma[i], ctx);
		EC_POINT_mul(curve, _temp2, NULL,
			vec_old_ciphertext[i].c2, context.stage_1_challenge->vec_rho[i], ctx);
		EC_POINT_invert(curve, _temp2, ctx);
		EC_POINT_add(curve, Phi2, Phi2, _temp1, ctx);
		EC_POINT_add(curve, Phi2, Phi2, _temp2, ctx);
	}

	EC_POINT *left = EC_POINT_new(curve);
	EC_POINT *right = EC_POINT_new(curve);

	for (int i = 0; i < context.k; i++) {
		EC_POINT_mul(curve, left, NULL,
			context.stage_1_proof->Gamma, context.stage_3_proof->vec_sigma[i], ctx);
		EC_POINT_add(curve, right,
			context.stage_1_proof->W[i], context.stage_2_proof->D[i], ctx);

		if (EC_POINT_cmp(curve, left, right, ctx) != 0) {
			EC_POINT_free(Phi1);
			EC_POINT_free(Phi2);
			EC_POINT_free(_temp1);
			EC_POINT_free(_temp2);
			EC_POINT_free(left);
			EC_POINT_free(right);
			return false;
		}
	}

	EC_POINT_mul(curve, left, NULL,
		G, context.stage_3_proof->tau, ctx);
	EC_POINT_add(curve, left,
		left, context.stage_1_proof->Lambda1, ctx);
	if (EC_POINT_cmp(curve, left, Phi1, ctx) != 0) {
		EC_POINT_free(Phi1);
		EC_POINT_free(Phi2);
		EC_POINT_free(_temp1);
		EC_POINT_free(_temp2);
		EC_POINT_free(left);
		EC_POINT_free(right);
		return false;
	}

	EC_POINT_mul(curve, left, NULL,
		global_public_key, context.stage_3_proof->tau, ctx);
	EC_POINT_add(curve, left,
		left, context.stage_1_proof->Lambda2, ctx);
	if (EC_POINT_cmp(curve, left, Phi2, ctx) != 0) {
		EC_POINT_free(Phi1);
		EC_POINT_free(Phi2);
		EC_POINT_free(_temp1);
		EC_POINT_free(_temp2);
		EC_POINT_free(left);
		EC_POINT_free(right);
		return false;
	}

	EC_POINT_free(Phi1);
	EC_POINT_free(Phi2);
	EC_POINT_free(_temp1);
	EC_POINT_free(_temp2);
	EC_POINT_free(left);
	EC_POINT_free(right);

	return true;
}












void pack(BIGNUM *num, BIGNUM *q, octetStream &o) {
	unsigned char bin_x[LENGTH];
	memset(bin_x, 0, LENGTH);

	BN_bn2binpad(num, bin_x, LENGTH);
	o.append(bin_x, LENGTH);
}
void pack(BIGNUM *num, octetStream &o) {
	unsigned char bin_x[LENGTH];
	memset(bin_x, 0, LENGTH);

	BN_bn2binpad(num, bin_x, LENGTH);
	o.append(bin_x, LENGTH);
}
void pack(EC_GROUP *curve, EC_POINT *point, octetStream &o) {
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BIGNUM *q = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	if (EC_POINT_is_at_infinity(curve, point) == 1) {
		BN_zero(x);
		BN_zero(y);
	}
	else
		EC_POINT_get_affine_coordinates_GFp(curve, point, x, y, ctx);

	EC_GROUP_get_order(curve, q, ctx);
	pack(x, q, o);
	pack(y, q, o);

	BN_free(x);
	BN_free(y);
	BN_free(q);
	BN_CTX_free(ctx);
}
void unpack(BIGNUM *num, octetStream &o) {
	unsigned char bin_x[LENGTH];

	o.consume(bin_x, LENGTH);
	BN_bin2bn(bin_x, LENGTH, num);
}
void unpack(EC_GROUP *curve, EC_POINT *point, octetStream &o) {
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	unpack(x, o);
	unpack(y, o);

	if ((BN_is_zero(x) == 1) && 
		(BN_is_zero(y) == 1)) {
		EC_POINT_set_to_infinity(curve, point);
	}
	else
		EC_POINT_set_affine_coordinates_GFp(curve, point, x, y, ctx);

	BN_free(x);
	BN_free(y);
	BN_CTX_free(ctx);
}