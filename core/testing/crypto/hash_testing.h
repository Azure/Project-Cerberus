// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_TESTING_H_
#define HASH_TESTING_H_


/* Input data for some test hashes. */
extern const uint8_t HASH_TESTING_PARTIAL_BLOCK_440[];
extern const uint32_t HASH_TESTING_PARTIAL_BLOCK_440_LEN;

extern const uint8_t HASH_TESTING_PARTIAL_BLOCK_448[];
extern const uint32_t HASH_TESTING_PARTIAL_BLOCK_448_LEN;

extern const uint8_t HASH_TESTING_PARTIAL_BLOCK_480[];
extern const uint32_t HASH_TESTING_PARTIAL_BLOCK_480_LEN;

extern const uint8_t HASH_TESTING_FULL_BLOCK_512[];
extern const uint32_t HASH_TESTING_FULL_BLOCK_512_LEN;

extern const uint8_t  HASH_TESTING_PARTIAL_BLOCK_952[];
extern const uint32_t HASH_TESTING_PARTIAL_BLOCK_952_LEN;

extern const uint8_t  HASH_TESTING_PARTIAL_BLOCK_960[];
extern const uint32_t HASH_TESTING_PARTIAL_BLOCK_960_LEN;

extern const uint8_t  HASH_TESTING_PARTIAL_BLOCK_992[];
extern const uint32_t HASH_TESTING_PARTIAL_BLOCK_992_LEN;

extern const uint8_t HASH_TESTING_FULL_BLOCK_1024[];
extern const uint32_t HASH_TESTING_FULL_BLOCK_1024_LEN;

extern const uint8_t HASH_TESTING_FULL_BLOCK_2048[];
extern const uint32_t HASH_TESTING_FULL_BLOCK_2048_LEN;

extern const uint8_t HASH_TESTING_FULL_BLOCK_4096[];
extern const uint32_t HASH_TESTING_FULL_BLOCK_4096_LEN;

extern const uint8_t HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[];
extern const uint32_t HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN;


/* Test hashes for different inputs and algorithms. */
extern const uint8_t SHA1_TEST_HASH[];
extern const uint8_t SHA256_TEST_HASH[];
extern const uint8_t SHA384_TEST_HASH[];
extern const uint8_t SHA512_TEST_HASH[];

extern const uint8_t SHA1_TEST_TEST_HASH[];
extern const uint8_t SHA256_TEST_TEST_HASH[];
extern const uint8_t SHA384_TEST_TEST_HASH[];
extern const uint8_t SHA512_TEST_TEST_HASH[];

extern const uint8_t SHA1_TEST2_HASH[];
extern const uint8_t SHA256_TEST2_HASH[];
extern const uint8_t SHA384_TEST2_HASH[];
extern const uint8_t SHA512_TEST2_HASH[];

extern const uint8_t SHA1_NOPE_HASH[];
extern const uint8_t SHA256_NOPE_HASH[];
extern const uint8_t SHA384_NOPE_HASH[];
extern const uint8_t SHA512_NOPE_HASH[];

extern const uint8_t SHA1_BAD_HASH[];
extern const uint8_t SHA256_BAD_HASH[];
extern const uint8_t SHA384_BAD_HASH[];
extern const uint8_t SHA512_BAD_HASH[];

extern const uint8_t SHA1_EMPTY_BUFFER_HASH[];
extern const uint8_t SHA256_EMPTY_BUFFER_HASH[];
extern const uint8_t SHA384_EMPTY_BUFFER_HASH[];
extern const uint8_t SHA512_EMPTY_BUFFER_HASH[];

extern const uint8_t SHA1_ZERO_BUFFER_HASH[];
extern const uint8_t SHA256_ZERO_BUFFER_HASH[];
extern const uint8_t SHA384_ZERO_BUFFER_HASH[];
extern const uint8_t SHA512_ZERO_BUFFER_HASH[];

extern const uint8_t SHA1_PARTIAL_BLOCK_440_HASH[];
extern const uint8_t SHA256_PARTIAL_BLOCK_440_HASH[];
extern const uint8_t SHA384_PARTIAL_BLOCK_440_HASH[];
extern const uint8_t SHA512_PARTIAL_BLOCK_440_HASH[];

extern const uint8_t SHA1_PARTIAL_BLOCK_448_HASH[];
extern const uint8_t SHA256_PARTIAL_BLOCK_448_HASH[];
extern const uint8_t SHA384_PARTIAL_BLOCK_448_HASH[];
extern const uint8_t SHA512_PARTIAL_BLOCK_448_HASH[];

extern const uint8_t SHA1_PARTIAL_BLOCK_480_HASH[];
extern const uint8_t SHA256_PARTIAL_BLOCK_480_HASH[];
extern const uint8_t SHA384_PARTIAL_BLOCK_480_HASH[];
extern const uint8_t SHA512_PARTIAL_BLOCK_480_HASH[];

extern const uint8_t SHA1_FULL_BLOCK_512_HASH[];
extern const uint8_t SHA256_FULL_BLOCK_512_HASH[];
extern const uint8_t SHA384_FULL_BLOCK_512_HASH[];
extern const uint8_t SHA512_FULL_BLOCK_512_HASH[];

extern const uint8_t SHA1_PARTIAL_BLOCK_952_HASH[];
extern const uint8_t SHA256_PARTIAL_BLOCK_952_HASH[];
extern const uint8_t SHA384_PARTIAL_BLOCK_952_HASH[];
extern const uint8_t SHA512_PARTIAL_BLOCK_952_HASH[];

extern const uint8_t SHA1_PARTIAL_BLOCK_960_HASH[];
extern const uint8_t SHA256_PARTIAL_BLOCK_960_HASH[];
extern const uint8_t SHA384_PARTIAL_BLOCK_960_HASH[];
extern const uint8_t SHA512_PARTIAL_BLOCK_960_HASH[];

extern const uint8_t SHA1_PARTIAL_BLOCK_992_HASH[];
extern const uint8_t SHA256_PARTIAL_BLOCK_992_HASH[];
extern const uint8_t SHA384_PARTIAL_BLOCK_992_HASH[];
extern const uint8_t SHA512_PARTIAL_BLOCK_992_HASH[];

extern const uint8_t SHA1_FULL_BLOCK_1024_HASH[];
extern const uint8_t SHA256_FULL_BLOCK_1024_HASH[];
extern const uint8_t SHA384_FULL_BLOCK_1024_HASH[];
extern const uint8_t SHA512_FULL_BLOCK_1024_HASH[];

extern const uint8_t SHA1_FULL_BLOCK_2048_HASH[];
extern const uint8_t SHA256_FULL_BLOCK_2048_HASH[];
extern const uint8_t SHA384_FULL_BLOCK_2048_HASH[];
extern const uint8_t SHA512_FULL_BLOCK_2048_HASH[];

extern const uint8_t SHA1_FULL_BLOCK_4096_HASH[];
extern const uint8_t SHA256_FULL_BLOCK_4096_HASH[];
extern const uint8_t SHA384_FULL_BLOCK_4096_HASH[];
extern const uint8_t SHA512_FULL_BLOCK_4096_HASH[];

extern const uint8_t SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH[];
extern const uint8_t SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH[];
extern const uint8_t SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH[];
extern const uint8_t SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH[];


/* HMAC testing. */
extern const uint8_t SHA1_HMAC_KEY[];
extern const uint8_t SHA256_HMAC_KEY[];
extern const uint8_t SHA384_HMAC_KEY[];
extern const uint8_t SHA512_HMAC_KEY[];

extern const uint8_t SHA1_TEST_HMAC[];
extern const uint8_t SHA256_TEST_HMAC[];
extern const uint8_t SHA384_TEST_HMAC[];
extern const uint8_t SHA512_TEST_HMAC[];



#endif /* HASH_TESTING_H_ */
