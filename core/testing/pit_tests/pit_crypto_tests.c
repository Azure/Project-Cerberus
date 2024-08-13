// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

/*
  Developed by AMI Inc. & Colorado State University.
  Contact person: Rakesh Podder. Email: rakeshpodder3@gmail.com
*/

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "platform.h"
#include "testing.h"
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "testing/crypto/ecc_testing.h"
#include "crypto/rng_mbedtls.h"
#include "asn1/base64_mbedtls.h"
#include "pit/pit.h"
#include "pit/pit_crypto.h"

TEST_SUITE_LABEL ("pit_crypto");
uint8_t AES_IV_TESTING[] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
};



static void test_keygenstate(CuTest *test){
    TEST_START;
    struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
    size_t keysize = (256 / 8);
    int state = -1;

    int status = pit_keygenstate(keysize, &priv_key, &pub_key, &state);
    CuAssertPtrNotNull(test, pub_key.context);
    CuAssertPtrNotNull(test, priv_key.context);
    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 1, state);


}

static void test_secretkey(CuTest *test){
    TEST_START;
    size_t keysize = (256 / 8);
    int state = -1;
    struct ecc_private_key priv_key1;
	struct ecc_public_key pub_key1;
    struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key2;


    struct ecc_engine_mbedtls engine;
    ecc_mbedtls_init (&engine);

    int status = pit_keygenstate(keysize, &priv_key1, &pub_key1, &state);
    CuAssertIntEquals(test, 1, status);

    status = pit_keygenstate(keysize, &priv_key2, &pub_key2, &state);
    CuAssertIntEquals(test, 1, status);

    int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key2);
    int shared_length2 = engine.base.get_shared_secret_max_length(&engine.base, &priv_key1);
    ecc_mbedtls_release(&engine);


    CuAssertIntEquals(test, shared_length2, shared_length);

    uint8_t secret1[shared_length];
    uint8_t secret2[shared_length];

    status = pit_secretkey(&priv_key1, &pub_key2, secret1, &state);
    CuAssertIntEquals(test, 1, status);

    status = pit_secretkey(&priv_key2, &pub_key1, secret2, &state);
    CuAssertIntEquals(test, 1, status);

    status = testing_validate_array (secret1, secret2, sizeof(secret1));
    CuAssertIntEquals (test, 0, status);

}

static void test_encryptionPID(CuTest *test){
    TEST_START;
    size_t keysize = (256 / 8);
    int state = -1;
    struct ecc_private_key priv_key1;
	struct ecc_public_key pub_key1;
    struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key2;

    struct ecc_engine_mbedtls engine;
    ecc_mbedtls_init (&engine);

    int status = pit_keygenstate(keysize, &priv_key1, &pub_key1, &state);
    CuAssertIntEquals(test, 1, status);

    status = pit_keygenstate(keysize, &priv_key2, &pub_key2, &state);
    CuAssertIntEquals(test, 1, status);

    int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key2);
    int shared_length2 = engine.base.get_shared_secret_max_length(&engine.base, &priv_key1);
    ecc_mbedtls_release(&engine);


    CuAssertIntEquals(test, shared_length2, shared_length);

    uint8_t secret1[shared_length];
    uint8_t secret2[shared_length];

    status = pit_secretkey(&priv_key1, &pub_key2, secret1, &state);
    CuAssertIntEquals(test, 1, status);

    status = pit_secretkey(&priv_key2, &pub_key1, secret2, &state);
    CuAssertIntEquals(test, 1, status);

    status = testing_validate_array (secret1, secret2, sizeof(secret1));
    CuAssertIntEquals (test, 0, status);

    int msg_length = 128;
    uint8_t msg[128] = "Hi!";
    uint8_t ciphertext[msg_length];
    uint8_t tag[16];    //Tags are always length 16

    status = pit_encryption(msg, msg_length, secret1, sizeof(secret1), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, ciphertext, &state);

    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 4, state);

}

static void test_decryption(CuTest *test){
    TEST_START;
    size_t keysize = (256 / 8);
    int state = -1;
    struct ecc_private_key priv_key1;
	struct ecc_public_key pub_key1;
    struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key2;


    struct ecc_engine_mbedtls engine;
    ecc_mbedtls_init (&engine);



    int status = pit_keygenstate(keysize, &priv_key1, &pub_key1, &state);
    CuAssertIntEquals(test, 1, status);

    status = pit_keygenstate(keysize, &priv_key2, &pub_key2, &state);
    CuAssertIntEquals(test, 1, status);

    int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key2);
    ecc_mbedtls_release(&engine);



    uint8_t secret1[shared_length];

    status = pit_secretkey(&priv_key1, &pub_key2, secret1, &state);
    CuAssertIntEquals(test, 1, status);

    int msg_length = 128;
    uint8_t msg[128] = "Hi there!";
    uint8_t ciphertext[msg_length];
    uint8_t tag[16];    //Tags are always length 16

    status = pit_encryption(msg, msg_length, secret1, sizeof(secret1), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, ciphertext, &state);
    
    uint8_t decrypted_msg[msg_length];
    status = pit_decryption(ciphertext, sizeof(ciphertext), secret1, sizeof(secret1), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, decrypted_msg, &state);
    CuAssertIntEquals(test, 1, status);
    
    status = testing_validate_array (msg, decrypted_msg, sizeof(decrypted_msg));
    CuAssertIntEquals (test, 0, status);
    
}

static void test_randomness(CuTest *test){
    TEST_START;
    struct rng_engine_mbedtls engine;
	uint8_t buffer[32] = {0};
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertTrue (test, (status != 0));
	rng_mbedtls_release (&engine);
    
}

static void test_OTPgen(CuTest *test){
    TEST_START;
    size_t keysize = (256 / 8);
    int state = -1;
    struct ecc_private_key priv_key1;
	struct ecc_public_key pub_key1;
    struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key2;


    struct ecc_engine_mbedtls engine;
    ecc_mbedtls_init (&engine);



    int status = pit_keygenstate(keysize, &priv_key1, &pub_key1, &state);
    CuAssertIntEquals(test, 1, status);

    status = pit_keygenstate(keysize, &priv_key2, &pub_key2, &state);
    CuAssertIntEquals(test, 1, status);

    int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key2);
    ecc_mbedtls_release (&engine);
    uint8_t secret[shared_length];

    status = pit_secretkey(&priv_key1, &pub_key2, secret, &state);
    CuAssertIntEquals(test, 1, status);

    size_t OTPsize = 32;
    uint8_t tag[16];
    uint8_t OTP[OTPsize];
    uint8_t OTPs[OTPsize];
    status = pit_OTPgen(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTP, OTPsize, OTPs, &state);
    CuAssertPtrNotNull(test, OTPs);
    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 6, state);
}

static void test_OTPvalidation(CuTest *test){
    TEST_START;
    size_t keysize = (256 / 8);
    int state = -1;
    struct ecc_private_key priv_key1;
	struct ecc_public_key pub_key1;
    struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key2;


    struct ecc_engine_mbedtls engine;
    ecc_mbedtls_init (&engine);



    int status = pit_keygenstate(keysize, &priv_key1, &pub_key1, &state);
    CuAssertIntEquals(test, 1, status);

    status = pit_keygenstate(keysize, &priv_key2, &pub_key2, &state);
    CuAssertIntEquals(test, 1, status);

    int shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key2);
    ecc_mbedtls_release (&engine);
    uint8_t secret[shared_length];

    status = pit_secretkey(&priv_key1, &pub_key2, secret, &state);
    CuAssertIntEquals(test, 1, status);

    size_t OTPsize = 32;
    uint8_t tag[16];
    uint8_t OTP[OTPsize];
    uint8_t OTPs[OTPsize];
    status = pit_OTPgen(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTP, OTPsize, OTPs, &state);
    CuAssertPtrNotNull(test, OTPs);
    CuAssertIntEquals(test, 1, status);
    CuAssertIntEquals(test, 6, state);

    bool result;
    status = pit_OTPvalidation(secret, sizeof(secret), AES_IV_TESTING, sizeof(AES_IV_TESTING), tag, OTPs, sizeof(OTPs), OTP, &result, &state);

    CuAssertIntEquals(test, 1, result);
    CuAssertIntEquals(test, 7, state);
    CuAssertIntEquals(test, 1, status);
}





TEST_SUITE_START (pit_crypto);
TEST (test_keygenstate);
TEST (test_secretkey);
TEST (test_encryptionPID);
TEST (test_randomness);
TEST (test_OTPgen);
TEST (test_OTPvalidation);
TEST (test_decryption);
TEST_SUITE_END;