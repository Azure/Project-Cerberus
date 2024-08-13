// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

/*
  Developed by AMI Inc. & Colorado State University.
  Contact person: Rakesh Podder. Email: rakeshpodder3@gmail.com
*/

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "crypto/aes_mbedtls.h"
#include "mbedtls/pk.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "crypto/rng_mbedtls.h"
#include <stdbool.h>
#include "pit.h"
#include <arpa/inet.h>
#include "pit_client.h"
#include "pit_crypto.h"


/**
 * Generates a key pair, sets the state appropriately
 * @param key_length The length of key to use in bytes. 256, 381, 521 bits (so X / 8 bytes) are the supported lengths
 * @param privkey Output for the initialized private key
 * @param pubkey Output for the initialized public key
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/

int pit_keygenstate(size_t key_length, struct ecc_private_key *privkey, struct ecc_public_key *pubkey, int *state){
  struct ecc_engine_mbedtls engine;   
  ecc_mbedtls_init (&engine);
  int status = engine.base.generate_key_pair(&engine.base, key_length, privkey, pubkey);
  
  *state = 1;
  ecc_mbedtls_release (&engine);
  if(status == 0){
    return SUCESS;
  }
  else{
    return PIT_CRYPTO_KEY_GENERATION_FAILED;
  }
  
}

/**
 * Generates a secret key - AES Shared Key
 * @param privkey The private key used to generate the secret
 * @param pubkey The public key used to generate the secret
 * @param secret An non-null output buffer to hold the generated shared secret
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/

int pit_secretkey(struct ecc_private_key *privkey, struct ecc_public_key *pubkey, uint8_t *secret, int *state){
  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  int shared_length = engine.base.get_shared_secret_max_length(&engine.base, privkey);
  uint8_t out[shared_length];
  int status = engine.base.compute_shared_secret(&engine.base, privkey, pubkey, out, sizeof (out));
  ecc_mbedtls_release (&engine);

  memcpy(secret, out, shared_length);

  if(shared_length != status){
    return PIT_CRYPTO_SECRET_KEY_NOT_EXPECTED_LENGTH;
  }
  *state = 3;
  return SUCESS;
}

/**
 * Uses AES-GCM encryption to encrypt a message into ciphertext using a secret key
 * @param msg A plaintext message you would like to encrypt
 * @param msg_size The size of the plaintext message
 * @param secret A secret key to use for encryption
 * @param secret_length The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param ciphertext An empty output buffer to hold the encrypted data. The ciphertext will be the same length as the plaintext
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_encryption(uint8_t *msg, size_t msg_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *ciphertext, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  
  aes_engine.base.set_key(&aes_engine.base, secret, secret_length);
  int status = aes_engine.base.encrypt_data (&aes_engine.base, msg, msg_size, AESIV,
		      AESIV_SIZE, ciphertext, msg_size, tag, 16);
  aes_mbedtls_release(&aes_engine);

  *state = 4;
  if(status != 0){
    return PIT_CRYPTO_ENCRYPTION_FAILED;
  }
  return SUCESS;

}

/**
 * Uses AES-GCM encryption to decrypt a message from ciphertext using a secret key
 * @param ciphertext The ciphertext you would like to decrypt
 * @param ciphertext_size The size of the ciphertext message
 * @param secret A secret key to use for encryption
 * @param secret_length The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param plaintext The buffer to hold the decrypted ciphertext (Will be the same size as the ciphertext)
 * @return 1 on success
*/

int pit_decryption(uint8_t *ciphertext, size_t ciphertext_size, uint8_t *secret, size_t secret_length, uint8_t *AESIV, size_t AESIV_SIZE, uint8_t *tag, uint8_t *plaintext, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  aes_engine.base.set_key (&aes_engine.base, secret, secret_length);

  int stat = aes_engine.base.decrypt_data (&aes_engine.base, ciphertext, ciphertext_size,
		tag, AESIV, AESIV_SIZE, plaintext, ciphertext_size);
  *state = 5;
  if(stat != 0){
    return PIT_CRYPTO_DECRYPTION_FAILED;
  }
  return SUCESS;
}

/**
 * A function to generate a random string representing OTP. Additionally, this function will encrypt that OTP using AES-GCM encryption, using the secret key for the AES encryption.
 * @param secret The secret key to encrypt the OTP with
 * @param secret_size The size of the secret key
 * @param AESIV An IV to use for encryption. A 12-byte IV is best (meets NIST standards)
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The output buffer to hold the GCM authentication tag. All tags will be 16 bytes
 * @param OTP An output buffer to hold a randomly generated OTP into
 * @param OTPSize The size the randomly generated OTP should be
 * @param OTPs An initialized but empty buffer to hold the encrypted OTP in (OTPs and OTP will be the same size)
 * @param state An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_OTPgen(uint8_t *secret,  size_t secret_size, uint8_t *AESIV, size_t aesiv_size, uint8_t *tag, uint8_t *OTP, size_t OTPsize, uint8_t *OTPs, int *state){
  struct rng_engine_mbedtls engine;
	int status;
	status = rng_mbedtls_init (&engine);
	status = engine.base.generate_random_buffer (&engine.base, OTPsize, OTP);
  if(status != 0){
    return PIT_CRYPTO_OTP_GENERATION_FAILED;
  }

status = pit_encryption(OTP, OTPsize, secret, secret_size, AESIV, aesiv_size, tag, OTPs, state);

if(status != 1){
  return PIT_CRYPTO_ENCRYPTION_FAILED;
}

*state = 6;
return SUCESS;
}

/**
 * Decrypts an encrypted OTP and compares it to a valid version of the OTP. If the OTP decrypts successfully and matches the valid OTP, the result parameter contains true.
 * @param secret The secret key used to decrypt OTPs
 * @param secret_size The size of the secret key
 * @param AESIV An IV to use for decryption. Must be the same as the IV provided to encrypt
 * @param AESIV_SIZE The size of the IV used for encryption
 * @param tag The AES-GCM tag for the ciphertext
 * @param OTPs A full buffer holding the value for OTPs (an encrypted OTP to validate against)
 * @param OTPs_size The size of OTPs
 * @param valOTP OTP to be validated against the decrypted OTP
 * @param result A boolean value to check whether the OTP was successfully validated
 * @param An int to hold the numerical value of the state
 * @return 1 on success
*/
int pit_OTPvalidation(uint8_t * secret, size_t secret_size, uint8_t *AESIV, size_t AESIV_size, uint8_t *tag, uint8_t *OTPs, size_t OTPs_size, uint8_t *valOTP, bool *result, int *state){
  struct aes_engine_mbedtls aes_engine;	
  aes_mbedtls_init (&aes_engine);
  aes_engine.base.set_key (&aes_engine.base, secret, secret_size);

  uint8_t plaintext[OTPs_size];
  int stat = aes_engine.base.decrypt_data (&aes_engine.base, OTPs, OTPs_size,
		tag, AESIV, AESIV_size, plaintext, OTPs_size);

  if(stat != 0){
    return PIT_CRYPTO_DECRYPTION_FAILED;
  }
  bool flag = true;

  for(int i = 0; i < (int)OTPs_size; i++){
    if(plaintext[i] != valOTP[i]){
      flag = false;
      break;
    }
  }
  *result = flag;
  *state = 7;
  if(flag){
    return SUCESS;
  }
  return PIT_CRYPTO_OTP_INVALID;
}


