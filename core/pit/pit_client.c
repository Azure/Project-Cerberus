// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

/*
  Developed by AMI Inc. & Colorado State University.
  Contact person: Rakesh Podder. Email: rakeshpodder3@gmail.com
*/

#include <arpa/inet.h>
#include "pit_client.h"
#include "crypto/ecc_mbedtls.h"
#include "mbedtls/ecdh.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/**
* Initiate a connection to desired server. Dependent on implementation (Socket vs i2c)
* @param desired_port The desired port to connect to the server on (Need not implement if using i2c)
* @return A file descriptor pointing to the socket (server implementation)
*/

int pit_connect(int desired_port){
  // Communicate w/ server, (will be i2c in final version, must be overwritten) (expand on this)
  char* ip = "127.0.0.1";
  int port = desired_port;

  int sock;
  struct sockaddr_in addr;


  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0){

    return PIT_I2C_CONNECTION_FAILURE;

  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {

    return PIT_I2C_CONNECTION_FAILURE;
  }
  return sock;
}

/**
 * On success, keyexchangestate should initialize pubkey_serv with the server's public key
 * @param pubkey_cli The initialized public key for the client (Machine using cerberus)
 * @param pubkey_serv An uninitialized public key to store the server's public key into
 * @return 1 on success
*/
    //May need to override depending on how pit_connect is implemented
int keyexchangestate(uint8_t *pubkey_cli, size_t pubkey_der_length, uint8_t *pubkey_serv){
  int sock = pit_connect(5572);

  send(sock, pubkey_cli, pubkey_der_length, 0); //Will always be length 91 for this curve, send client public key (DER Format)

  recv(sock, pubkey_serv, pubkey_der_length, 0); //Receive the server's public key (DER Format)

  return SUCCESS;
}

/**
 * Sends OTPs, AES IV, and the AES-GCM Tag for OTP encryption to the server, receives the server's encrypted message and tag for that message back
 * @param OTPs The Encrypted OTP to send
 * @param OTPs_size Size (in bytes) of the OTPs
 * @param unlock_aes_iv The AES IV used to encrypt the OTP into OTPs
 * @param unlock_aes_iv_size Size (in bytes) of the unlock_aes_iv param
 * @param OTP_tag The AES-GCM Tag generated when encrypting OTP into OTPs
 * @param server_encrypted_message An empty buffer to hold the server's response message (which will then be validated in the unlock API)
 * @param server_tag The AES-GCM tag for the server's encrypted message
 * @return 1 on success
*/

int send_unlock_info(uint8_t *OTPs, size_t OTPs_size, uint8_t *unlock_aes_iv, size_t unlock_aes_iv_size, uint8_t *OTP_tag, uint8_t *server_encrypted_message, uint8_t *server_tag){
  int sock = pit_connect(5573);
  send(sock, OTPs, OTPs_size, 0);                    //Send OTPs
  send(sock, unlock_aes_iv, unlock_aes_iv_size, 0);  //Send the IV for the AES cipher
  send(sock, OTP_tag, 16, 0);                        //Send AES-GCM tag

  // printf("Please Enter your OTP:\n");
  // scanf("%d", &server_encrypted_message);
  recv(sock, server_tag, 16, 0);                      //Receive server's message tag

  return SUCCESS;
}


int receive_product_info(uint8_t *EncryptedProductID, uint8_t *EncryptedProductIDTag, size_t ProductIDSize, uint8_t *aes_iv, size_t aes_iv_size){
  //printf("Trying to connect in receive_product_info...\n");
  int sock = pit_connect(5574);
  send(sock, aes_iv, aes_iv_size, 0);
  recv(sock, EncryptedProductID, ProductIDSize, 0);
  recv(sock, EncryptedProductIDTag, 16, 0);
  return SUCCESS;

}