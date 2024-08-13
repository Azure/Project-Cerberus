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
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "crypto/rng_mbedtls.h"
#include "pit_crypto.h"
#include <stdbool.h>
#include "pit.h"
#include <arpa/inet.h>
#include "pit_client.h"


uint8_t *shared_secret;           // Global variable to store secret key;
int shared_length;                // Secret Key Length;
struct ecc_private_key priv_key;  // ECC Private Key;
struct ecc_public_key pub_key;    // ECC Public Key;
uint8_t class_OTPs [128];         // OTP Varibale;
int state;                        // State of PIT Protocol;

/**
 * Sets up needed variables and sets the systems state to lock.
 * Exchanges keys with the server to create a secret key
 * @param secret A 32-byte empty array which will be loaded with the shared secret
 * @return 1 on success
*/
int pit_Lock(uint8_t *secret){

  size_t keysize = (256 / 8);

  int key_stat = pit_keygenstate(keysize, &priv_key, &pub_key, &state);
  if(key_stat != 1){
    return PIT_KEY_GEN_FAILURE;
  }

  struct ecc_engine_mbedtls engine;
  ecc_mbedtls_init (&engine);
  struct ecc_public_key pub_key_serv;
  shared_length = engine.base.get_shared_secret_max_length(&engine.base, &priv_key);
  shared_secret = malloc( 8 * shared_length);

  uint8_t *pub_der = NULL;
  size_t der_length;
  engine.base.get_public_key_der (&engine.base, &pub_key, &pub_der, &der_length);

  uint8_t buffer[der_length];
  bzero(buffer, der_length);

  keyexchangestate(pub_der, der_length, buffer);
  
  engine.base.init_public_key(&engine.base, buffer, der_length, &pub_key_serv);
  ecc_mbedtls_release (&engine);
  key_stat = pit_secretkey(&priv_key, &pub_key_serv, secret, &state);

  if(key_stat != 1){
    return PIT_SECRET_KEY_GEN_FAILURE;
  }

  memcpy(shared_secret, secret, shared_length);
  state = 0;
  return SUCCESS;
}

/**
 * Unlocks the state of the machine by validating OTP
 * Creates an OTP, then encrypts it as OTPs. Sends OTPs to the server.
 * Server then encrypts OTPs again, then sends it back to the client.
 * Client decrypts server's message and validates OTPs against original OTP
 * @return 1 on success
*/

int pit_Unlock(){
  int my_state;
  uint8_t unlock_aes_iv[] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b
  };

  int product_id_size = 16;
  uint8_t ePID[16];
  uint8_t ePID_tag[16];
  bool isValidPID = false;
  printf("User initiated Unlock Request......\n");

  receive_product_info(ePID, ePID_tag, product_id_size, unlock_aes_iv, sizeof(unlock_aes_iv));

  int pid_status = pit_OTPvalidation(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), ePID_tag, ePID, sizeof(ePID), (unsigned char *)PRODUCT_ID, &isValidPID, &my_state);
  if(pid_status==1)
      printf("PRODUCT ID Validation Successful. pid_status is: %d\n", pid_status );
  else
      printf("PRODUCT ID Validation Fails. pid_status is: %d\n", pid_status );

  int otp_size = 128;
  uint8_t OTP_tag[16];
  uint8_t OTP[otp_size];
  uint8_t OTPs[otp_size];

  int status = pit_OTPgen(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), OTP_tag, OTP, otp_size, OTPs, &my_state);
  memcpy(class_OTPs, OTPs, otp_size);
  if(status != 1){
    return PIT_OTP_GENERATION_FAILURE;
  }
  printf("OTP Generation and Encryption Successful.\n");

  uint8_t serv_enc[128];
  uint8_t server_encrypted_message[128];
  uint8_t server_tag[16];
  //Send OTPs to server
  send_unlock_info(OTPs, sizeof(OTPs), unlock_aes_iv, sizeof(unlock_aes_iv), OTP_tag, serv_enc, server_tag);
  printf("Encrypted OTP sent to Server.\n");

  bool isValid = false;
  printf("Please Enter your OTP:\n");
  unsigned int temp_server_encrypted_message;
  scanf("%u", &temp_server_encrypted_message);
  if (temp_server_encrypted_message > UINT8_MAX) {
      printf("Value out of range for uint8_t.\n");
      return 1;
  }
  *server_encrypted_message = (uint8_t)temp_server_encrypted_message;
  
  pit_OTPvalidation(shared_secret, shared_length, unlock_aes_iv, sizeof(unlock_aes_iv), server_tag, server_encrypted_message, sizeof(server_encrypted_message), OTP, &isValid, &my_state);
  if(pid_status==1)
      printf("OTP Validation Successful. pid_status is: %d\n", pid_status );
  else
      printf("OTP Validation Fails. pid_status is: %d\n", pid_status );
  exit(20); //TODO : Remove
  if(isValid){
    state = 7; 
    return SUCCESS;
  }
  return PIT_UNLOCK_NOT_VALID;

}

/** Gets the state of the system
 * @return The numerical value of the state of the system at the moment of calling
*/
int get_state(){
  return state;
}

/**
 * Get the encrypted OTP (OTPs) from the system
 * @param OTPs Empty buffer to hold the encrypted OTP into
 * @return 1 on success
*/
int get_OTPs(uint8_t *OTPs){
  memcpy(OTPs, class_OTPs, 128);  //Size of OTPs is always 128
  return 1;
}



