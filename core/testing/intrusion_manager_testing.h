// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_MANAGER_TESTING_H_
#define INTRUSION_MANAGER_TESTING_H_


/**
 * Test event ID to use for intrusion measurements.
 */
#define	INTRUSION_MANAGER_TESTING_EVENT_ID			0xdeadbeef

/**
 * Expected version for intrusion measurements.
 */
#define	INTRUSION_MANAGER_TESTING_EVENT_VERSION		0

extern const uint8_t INTRUSION_MANAGER_TESTING_NO_INTRUSION[];
extern const uint8_t INTRUSION_MANAGER_TESTING_INTRUSION[];
extern const uint8_t INTRUSION_MANAGER_TESTING_UNKNOWN[];

/**
 * Length of the intrusion manager measurements.
 */
#define	INTRUSION_MANAGER_TESTING_DIGEST_LEN	SHA256_HASH_LENGTH


#endif /* INTRUSION_MANAGER_TESTING_H_ */
