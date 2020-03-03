// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_TESTING_H_
#define SIGNATURE_TESTING_H_

#include "crypto/hash.h"


extern const uint8_t SIG_HASH_TEST[];
extern const uint8_t SIG_HASH_TEST2[];
extern const uint8_t SIG_HASH_NOPE[];
extern const uint8_t SIG_HASH_BAD[];

#define	SIG_HASH_LEN	SHA256_HASH_LENGTH


#endif /* SIGNATURE_TESTING_H_ */
