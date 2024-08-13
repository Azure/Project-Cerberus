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
#include <stdbool.h>


#define PRODUCT_ID "ABCDEFGHIJKLMNOP"
#define SUCCESS 1

int pit_Lock(uint8_t *secret);

int pit_Unlock();

int get_state();

int get_OTPs(uint8_t *OTPs);

#define	PIT_ERROR(code)		ROT_ERROR (ROT_MODULE_PIT, code)

/**
 * Error codes that can be generated by a hash or HMAC engine.
 */
enum {
  PIT_KEY_GEN_FAILURE = PIT_ERROR (0x00),	/** Failure when generating a key-pair*/
  PIT_SECRET_KEY_GEN_FAILURE = PIT_ERROR (0x01), /** Failure when generating secret-key*/
  PIT_OTP_GENERATION_FAILURE = PIT_ERROR(0x02), /** Failure when generating OTP*/
  PIT_UNLOCK_NOT_VALID = PIT_ERROR(0x03),
};