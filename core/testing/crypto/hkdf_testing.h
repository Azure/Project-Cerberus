// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HKDF_TESTING_H_
#define HKDF_TESTING_H_

#include <stddef.h>
#include <stdint.h>


extern const uint8_t HKDF_TESTING_EXTRACT_IKM[];
extern const size_t HKDF_TESTING_EXTRACT_IKM_LEN;

/**
 * Input keying material for HKDF-Extract testing with SHA-1.  Taken from RFC 5869 test vectors.
 */
#define	HKDF_TESTING_EXTRACT_IKM_SHA1			HKDF_TESTING_EXTRACT_IKM
#define	HKDF_TESTING_EXTRACT_IKM_SHA1_LEN		11

extern const uint8_t HKDF_TESTING_EXTRACT_IKM_LONG[];
extern const size_t HKDF_TESTING_EXTRACT_IKM_LONG_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_IKM_NO_SALT[];
extern const size_t HKDF_TESTING_EXTRACT_IKM_NO_SALT_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_SALT[];
extern const size_t HKDF_TESTING_EXTRACT_SALT_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_SALT_LONG[];
extern const size_t HKDF_TESTING_EXTRACT_SALT_LONG_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_SHA256[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_SHA256_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_LONG_SHA256[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_LONG_SHA256_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_ZERO_SALT_SHA256[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_ZERO_SALT_SHA256_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_NO_SALT_SHA256[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_NO_SALT_SHA256_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_SHA1[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_SHA1_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_LONG_SHA1[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_LONG_SHA1_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_ZERO_SALT_SHA1[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_ZERO_SALT_SHA1_LEN;

extern const uint8_t HKDF_TESTING_EXTRACT_PRK_NO_SALT_SHA1[];
extern const size_t HKDF_TESTING_EXTRACT_PRK_NO_SALT_SHA1_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_INFO[];
extern const size_t HKDF_TESTING_EXPAND_INFO_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_INFO_LONG[];
extern const size_t HKDF_TESTING_EXPAND_INFO_LONG_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_OKM_SHA256[];
extern const size_t HKDF_TESTING_EXPAND_OKM_SHA256_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_OKM_LONG_SHA256[];
extern const size_t HKDF_TESTING_EXPAND_OKM_LONG_SHA256_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA256[];
extern const size_t HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA256_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_OKM_SHA1[];
extern const size_t HKDF_TESTING_EXPAND_OKM_SHA1_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_OKM_LONG_SHA1[];
extern const size_t HKDF_TESTING_EXPAND_OKM_LONG_SHA1_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1[];
extern const size_t HKDF_TESTING_EXPAND_OKM_NO_INFO_SHA1_LEN;

extern const uint8_t HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1[];
extern const size_t HKDF_TESTING_EXPAND_OKM_NO_SALT_SHA1_LEN;


#endif	/* HKDF_TESTING_H_ */
