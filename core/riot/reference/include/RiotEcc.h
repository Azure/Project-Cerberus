#ifndef _RIOT_CRYPTO_ECC_H
#define _RIOT_CRYPTO_ECC_H
/******************************************************************************
 * Copyright (c) 2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE in the project root.
 */

//
// 4-MAY-2015; RIoT adaptation (DennisMa;MSFT).
//
#include <stdbool.h>
#include "RiotTarget.h"
#include "RiotStatus.h"
#include "crypto/rng.h"
#include "crypto/hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define     ECDSA_SIGN      YES
#define     ECDSA_VERIFY    YES
#define     ECDH_IN         NO
#define     ECDH_OUT        YES

#if ECDSA_SIGN || ECDH_OUT
#define USES_EPHEMERAL      YES
#else
#define USES_EPHEMERAL      NO
#endif

#define BIGLEN 9
//
// For P256 bigval_t types hold 288-bit 2's complement numbers (9
// 32-bit words).  For P192 they hold 224-bit 2's complement numbers
// (7 32-bit words).
//
// The representation is little endian by word and native endian
// within each word.
// The least significant word of the value is in the 0th word and there is an
// extra word of zero at the top.
//
#define RIOT_ECC_PRIVATE_BYTES	(4 * (BIGLEN - 1))
#define RIOT_ECC_COORD_BYTES	RIOT_ECC_PRIVATE_BYTES
#define RIOT_ECC_SIG_BYTES		RIOT_ECC_PRIVATE_BYTES
//
// 4 is in lieu of sizeof(uint32_t), so that the macro is usable in #if conditions
//
typedef struct {
    uint32_t data[BIGLEN];
} bigval_t;

typedef struct {
    bigval_t x;
    bigval_t y;
    uint32_t infinity;
} affine_point_t;

typedef struct {
    bigval_t r;
    bigval_t s;
} ECDSA_sig_t;

typedef struct {
	bigval_t d;
	affine_point_t Q;	
} riot_ecdh_keypair;

typedef bigval_t ecc_privatekey;
typedef affine_point_t ecc_publickey;
typedef affine_point_t ecc_secret;
typedef ECDSA_sig_t ecc_signature;
typedef riot_ecdh_keypair ecc_keypair;

void set_drbg_seed(uint8_t *buf, size_t length);

//
// Convert a number from big endian by uint8_t to bigval_t. If the
// size of the input number is larger than the initialization size
// of a bigval_t ((BIGLEN - 1) * 4), it will be quietly truncated.
//
// @param out  pointer to the bigval_t to be produced
// @param in   pointer to the big-endian value to convert
// @param inSize  number of bytes in the big-endian value
//
void
BigIntToBigVal(bigval_t *tgt, const void *in, size_t inSize);

//
// Convert a number from bigval_t to big endian by uint8_t.
// The conversion will stop after the first (BIGLEN - 1) words have been converted.
// The output size must be (BIGLEN = 1) * 4 bytes long.
//
// @param out  pointer to the big endian value to be produced
// @param in   pointer to the bigval_t to convert
//
void
BigValToBigInt(void *out, const bigval_t *tgt);

//
// Generates the Ephemeral Diffie-Hellman key pair.
//
// @param publicKey The output public key
// @param privateKey The output private key
// @param rng The random number generator engine
//
// @return  - RIOT_SUCCESS if the key pair is successfully generated.
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_GenerateDHKeyPair(ecc_publickey *publicKey, ecc_privatekey *privateKey, struct rng_engine *rng);

//
// Generates the Diffie-Hellman share secret.
//
// @param peerPublicKey The peer's public key
// @param privateKey The private key
// @param secret The output share secret
//
// @return  - RIOT_SUCCESS if the share secret is successfully generated.
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_GenerateShareSecret(ecc_publickey *peerPublicKey,
                                     ecc_privatekey *privateKey,
                                     ecc_secret *secret);
//
// Generates the DSA key pair.
//
// @param publicKey The output public key
// @param privateKey The output private key
// @param rng The random number generator engine
// @return  - RIOT_SUCCESS if the key pair is successfully generated
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_GenerateDSAKeyPair(ecc_publickey *publicKey, ecc_privatekey *privateKey, struct rng_engine *rng);

//
// Derives a DSA key pair from the source value
//
// @param publicKey  OUT: public key
// @param privateKey OUT: output private key
// @param srcVal     IN: Source value for derivation
// @param srcSize    IN: Source size. Should not exceed RIOT_ECC_PRIVATE_bytes.
// @return  - RIOT_SUCCESS if the keypair is successfully derived
//          - RIOT_FAILURE otherwise
//
RIOT_STATUS
RIOT_DeriveDsaKeyPair(ecc_publickey *publicKey, ecc_privatekey *privateKey,
                      const uint8_t *srcVal, size_t srcSize);

//
// Sign a digest using the DSA key
// @param digest The digest to sign
// @param digest_size The digest buffer size
// @param signingPrivateKey The private key
// @param buf The buffer to store the signature
// @param buf_len The buffer size
// @param rng The random number generator engine
// @param out_len The length in bytes of the DER encoded signed digest
// @return  - RIOT_SUCCESS if the signing process succeeds
//          - RIOT_FAILURE otherwise
RIOT_STATUS RIOT_DSASignDigest(const uint8_t *digest, size_t digest_size, const ecc_privatekey *signingPrivateKey,
	uint8_t *buf, size_t buf_len, struct rng_engine *rng, int *out_len);

//
// Sign a buffer using the DSA key
// @param buf The buffer to sign
// @param len The buffer len
// @param signingPrivateKey The signing private key
// @param rng The random number generator engine
// @param hash The hash engine
// @param sig The output signature
// @return  - RIOT_SUCCESS if the signing process succeeds
//          - RIOT_FAILURE otherwise
RIOT_STATUS RIOT_DSASign(const uint8_t *buf, uint16_t len, const ecc_privatekey *signingPrivateKey,
	struct rng_engine *rng, struct hash_engine *hash, ecc_signature *sig);

//
// Verify DSA signature of a digest
// @param digest The digest to sign
// @param digest_size The size of the digest buffer
// @param sig The signature
// @param pubKey The signing public key
// @return  - RIOT_SUCCESS if the signature verification succeeds
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_DSAVerifyDigest(const uint8_t *digest, size_t digest_size, const ecc_signature *sig, const ecc_publickey *pubKey);

//
// Verify DSA signature of a buffer
// @param buf The buffer to sign
// @param len The buffer len
// @param sig The signature
// @param pubKey The signing public key
// @param hash The hash engine
// @return  - RIOT_SUCCESS if the signature verification succeeds
//          - RIOT_ERR_SECURITY otherwise
//
RIOT_STATUS RIOT_DSAVerify(const uint8_t *buf, uint16_t len, const ecc_signature *sig, const ecc_publickey *pubKey, struct hash_engine *hash);

//
// Checks if the private key integer is a valid value
// @param priv_key The private key
// @return - RIOT_SUCCESS if the key is a valid value
//		   - RIOT_FAILURE otherwise			 
//
RIOT_STATUS RIOT_DSA_check_privkey(const ecc_privatekey *priv_key);

//
// Checks if the public key is a valid value
// @param key The public key
// @return - RIOT_SUCCESS if the key is a valid value
//		   - RIOT_FAILURE otherwise			 
//
RIOT_STATUS RIOT_DSA_check_pubkey(const ecc_keypair *key);

//
// Encodes a signature in ASN.1 DER format
// @param sig The signature to encode
// @param buf The buffer to store the encoded signature
// @param buf_len The buffer size
// @param out_len The length in bytes of the encoded signature
// @return - RIOT_SUCCESS if the signature encoding succeeds
//         - RIOT_FAILURE otherwise 
//
RIOT_STATUS RIOT_DSA_encode_signature(const ecc_signature *sig, uint8_t *buf, size_t buf_len, int *out_len);

//
// Decodes an ASN.1 DER encoded signature
// @param rs_sig The decoded signature
// @param der_sig The DER encoded signature
// @return - RIOT_SUCCESS if the signature decoding succeeds
//         - RIOT_FAILURE otherwise
//
RIOT_STATUS RIOT_DSA_decode_signature(ecc_signature *rs_sig, const uint8_t *der_sig, size_t sig_len);

//
// Computes the size in bytes of the private key
// @param priv_key The private key
// @return size of the private key 
//         0 otherwise
//
int RIOT_DSA_size(const ecc_keypair *key);

//
// Initializes an ECC key pair using the private and public DER encoded keys
// @param private_key The private key to initialize
// @param public_key The public key to initialize
// @param der_priv_key The DER encoded private key
// @param priv_key_len The DER encoded private key length
// @param der_pub_key The DER encoded public key
// @param pub_key_len The DER encoded public key size
// @return - RIOT_SUCCESS if the key pair initialization succeeds
//         - RIOT_FAILURE otherwise 
//
RIOT_STATUS RIOT_DSA_init_key_pair(ecc_keypair *private_key, ecc_keypair *public_key, const uint8_t *der_priv_key, size_t priv_key_len, const uint8_t *der_pub_key, size_t pub_key_len);

#ifdef __cplusplus
}
#endif

#endif
