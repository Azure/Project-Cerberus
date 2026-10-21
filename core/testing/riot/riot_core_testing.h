// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_CORE_TESTING_H_
#define RIOT_CORE_TESTING_H_

#include <stddef.h>
#include <stdint.h>
#include "asn1/x509_extension_builder.h"
#include "crypto/ecc.h"


extern const uint8_t RIOT_CORE_DEVICE_ID_OID[];
extern const size_t RIOT_CORE_DEVICE_ID_OID_LEN;

extern const uint8_t RIOT_CORE_CDI[];
extern const size_t RIOT_CORE_CDI_LEN;

extern const uint8_t RIOT_CORE_CDI_HASH[];
extern const size_t RIOT_CORE_CDI_HASH_LEN;
extern const uint8_t RIOT_CORE_CDI_HASH_384[];
extern const size_t RIOT_CORE_CDI_HASH_384_LEN;
extern const uint8_t RIOT_CORE_CDI_HASH_512[];
extern const size_t RIOT_CORE_CDI_HASH_512_LEN;

extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_TEST_LABEL_LEN;
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_TEST_CONTEXT_LEN;

extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_TEST_256_DATA[];
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_TEST_384_DATA[];
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_TEST_521_DATA_1[];
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_TEST_521_DATA_2[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_TEST_DATA_LEN;

extern const uint8_t RIOT_CORE_DEVICE_ID_KDF[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_LEN;
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_384[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_384_LEN;
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_521_OUT_1[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_521_OUT_1_LEN;
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_521_OUT_2[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_521_OUT_2_LEN;
extern const uint8_t RIOT_CORE_DEVICE_ID_KDF_521[];
extern const size_t RIOT_CORE_DEVICE_ID_KDF_521_LEN;

extern const uint8_t RIOT_CORE_DEVICE_ID[];
extern const size_t RIOT_CORE_DEVICE_ID_LEN;
extern const uint8_t RIOT_CORE_DEVICE_ID_384[];
extern const size_t RIOT_CORE_DEVICE_ID_384_LEN;
extern const uint8_t RIOT_CORE_DEVICE_ID_521[];
extern const size_t RIOT_CORE_DEVICE_ID_521_LEN;

extern const uint8_t RIOT_CORE_SERIAL_KDF_TEST_DATA[];
extern const size_t RIOT_CORE_SERIAL_KDF_TEST_DATA_LEN;

extern const size_t RIOT_CORE_SERIAL_LEN;

extern const uint8_t RIOT_CORE_DEVID_SERIAL[];
extern const size_t RIOT_CORE_DEVID_SERIAL_LEN;
extern const uint8_t RIOT_CORE_DEVID_SERIAL_384[];
extern const size_t RIOT_CORE_DEVID_SERIAL_384_LEN;
extern const uint8_t RIOT_CORE_DEVID_SERIAL_521[];
extern const size_t RIOT_CORE_DEVID_SERIAL_521_LEN;

extern const char RIOT_CORE_DEVID_NAME[];
extern const size_t RIOT_CORE_DEVID_NAME_LEN;
extern const char RIOT_CORE_DEVID_NAME_384[];
extern const size_t RIOT_CORE_DEVID_NAME_384_LEN;
extern const char RIOT_CORE_DEVID_NAME_521[];
extern const size_t RIOT_CORE_DEVID_NAME_521_LEN;
extern const char RIOT_CORE_DEVID_NAME_521_TRUNCATED[];
extern const size_t RIOT_CORE_DEVID_NAME_521_TRUNCATED_LEN;

extern const uint8_t RIOT_CORE_DEVID_CSR[];
extern const size_t RIOT_CORE_DEVID_CSR_LEN;
extern const uint8_t RIOT_CORE_DEVID_CSR_384[];
extern const size_t RIOT_CORE_DEVID_CSR_384_LEN;
extern const uint8_t RIOT_CORE_DEVID_CSR_521[];
extern const size_t RIOT_CORE_DEVID_CSR_521_LEN;

extern const uint8_t RIOT_CORE_DEVID_CERT[];
extern const size_t RIOT_CORE_DEVID_CERT_LEN;
extern const uint8_t RIOT_CORE_DEVID_CERT_384[];
extern const size_t RIOT_CORE_DEVID_CERT_384_LEN;
extern const uint8_t RIOT_CORE_DEVID_CERT_521[];
extern const size_t RIOT_CORE_DEVID_CERT_521_LEN;

extern const uint8_t RIOT_CORE_DEVID_SIGNED_CERT[];
extern const size_t RIOT_CORE_DEVID_SIGNED_CERT_LEN;
extern const uint8_t RIOT_CORE_DEVID_SIGNED_CERT_384[];
extern const size_t RIOT_CORE_DEVID_SIGNED_CERT_384_LEN;
extern const uint8_t RIOT_CORE_DEVID_SIGNED_CERT_521[];
extern const size_t RIOT_CORE_DEVID_SIGNED_CERT_521_LEN;

extern const uint8_t RIOT_CORE_DEVID_INTR_SIGNED_CERT[];
extern const size_t RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
extern const uint8_t RIOT_CORE_DEVID_INTR_SIGNED_CERT_384[];
extern const size_t RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN;
extern const uint8_t RIOT_CORE_DEVID_INTR_SIGNED_CERT_521[];
extern const size_t RIOT_CORE_DEVID_INTR_SIGNED_CERT_521_LEN;

extern const char *RIOT_CORE_ALIAS_VERSION;
extern const uint32_t RIOT_CORE_ALIAS_SVN;

extern const uint8_t RIOT_CORE_FWID[];
extern const size_t RIOT_CORE_FWID_LEN;
extern const uint8_t RIOT_CORE_FWID_SHA384[];
extern const size_t RIOT_CORE_FWID_SHA384_LEN;
extern const uint8_t RIOT_CORE_FWID_SHA512[];
extern const size_t RIOT_CORE_FWID_SHA512_LEN;

extern const uint8_t RIOT_CORE_ALIAS_TCBINFO_DATA[];
extern const size_t RIOT_CORE_ALIAS_TCBINFO_DATA_LEN;
extern const struct x509_extension RIOT_CORE_ALIAS_TCBINFO_EXTENSION;

extern const uint8_t RIOT_CORE_ALIAS_TCBINFO_DATA_SHA384[];
extern const size_t RIOT_CORE_ALIAS_TCBINFO_DATA_SHA384_LEN;
extern const struct x509_extension RIOT_CORE_ALIAS_TCBINFO_EXTENSION_SHA384;

extern const uint8_t RIOT_CORE_ALIAS_TCBINFO_DATA_SHA512[];
extern const size_t RIOT_CORE_ALIAS_TCBINFO_DATA_SHA512_LEN;
extern const struct x509_extension RIOT_CORE_ALIAS_TCBINFO_EXTENSION_SHA512;

extern const uint8_t RIOT_CORE_FWID_KDF[];
extern const size_t RIOT_CORE_FWID_KDF_LEN;
extern const uint8_t RIOT_CORE_FWID_KDF_384[];
extern const size_t RIOT_CORE_FWID_KDF_384_LEN;
extern const uint8_t RIOT_CORE_FWID_KDF_521[];
extern const size_t RIOT_CORE_FWID_KDF_521_LEN;

extern const uint8_t RIOT_CORE_ALIAS_KDF_TEST_LABEL[];
extern const size_t RIOT_CORE_ALIAS_KDF_TEST_LABEL_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KDF_TEST_CONTEXT[];
extern const size_t RIOT_CORE_ALIAS_KDF_TEST_CONTEXT_LEN;

extern const uint8_t RIOT_CORE_ALIAS_KDF_TEST_256_DATA[];
extern const uint8_t RIOT_CORE_ALIAS_KDF_TEST_384_DATA[];
extern const uint8_t RIOT_CORE_ALIAS_KDF_TEST_521_DATA_1[];
extern const uint8_t RIOT_CORE_ALIAS_KDF_TEST_521_DATA_2[];
extern const size_t RIOT_CORE_ALIAS_KDF_TEST_DATA_LEN;

extern const uint8_t RIOT_CORE_ALIAS_KDF[];
extern const size_t RIOT_CORE_ALIAS_KDF_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KDF_384[];
extern const size_t RIOT_CORE_ALIAS_KDF_384_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KDF_521_OUT_1[];
extern const size_t RIOT_CORE_ALIAS_KDF_521_OUT_1_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KDF_521_OUT_2[];
extern const size_t RIOT_CORE_ALIAS_KDF_521_OUT_2_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KDF_521[];
extern const size_t RIOT_CORE_ALIAS_KDF_521_LEN;

extern const uint8_t RIOT_CORE_ALIAS_KEY[];
extern const size_t RIOT_CORE_ALIAS_KEY_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KEY_384[];
extern const size_t RIOT_CORE_ALIAS_KEY_384_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KEY_521[];
extern const size_t RIOT_CORE_ALIAS_KEY_521_LEN;

extern const uint8_t RIOT_CORE_ALIAS_KEY_NO_PUBKEY[];
extern const size_t RIOT_CORE_ALIAS_KEY_NO_PUBKEY_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KEY_NO_PUBKEY_384[];
extern const size_t RIOT_CORE_ALIAS_KEY_NO_PUBKEY_384_LEN;
extern const uint8_t RIOT_CORE_ALIAS_KEY_NO_PUBKEY_521[];
extern const size_t RIOT_CORE_ALIAS_KEY_NO_PUBKEY_521_LEN;

extern const uint8_t RIOT_CORE_ALIAS_PUBLIC_KEY[];
extern const size_t RIOT_CORE_ALIAS_PUBLIC_KEY_LEN;
extern const uint8_t RIOT_CORE_ALIAS_PUBLIC_KEY_384[];
extern const size_t RIOT_CORE_ALIAS_PUBLIC_KEY_384_LEN;
extern const uint8_t RIOT_CORE_ALIAS_PUBLIC_KEY_521[];
extern const size_t RIOT_CORE_ALIAS_PUBLIC_KEY_521_LEN;

extern const uint8_t RIOT_CORE_ALIAS_PUBLIC_KEY_RAW[];
extern const size_t RIOT_CORE_ALIAS_PUBLIC_KEY_RAW_LEN;
extern const uint8_t RIOT_CORE_ALIAS_PUBLIC_KEY_384_RAW[];
extern const size_t RIOT_CORE_ALIAS_PUBLIC_KEY_384_RAW_LEN;
extern const uint8_t RIOT_CORE_ALIAS_PUBLIC_KEY_521_RAW[];
extern const size_t RIOT_CORE_ALIAS_PUBLIC_KEY_521_RAW_LEN;
extern const struct ecc_point_public_key RIOT_CORE_ALIAS_PUBLIC_KEY_POINT;
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key RIOT_CORE_ALIAS_PUBLIC_KEY_384_POINT;
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
extern const struct ecc_point_public_key RIOT_CORE_ALIAS_PUBLIC_KEY_521_POINT;
#endif

extern const uint8_t RIOT_CORE_ALIAS_SERIAL[];
extern const size_t RIOT_CORE_ALIAS_SERIAL_LEN;
extern const uint8_t RIOT_CORE_ALIAS_SERIAL_384[];
extern const size_t RIOT_CORE_ALIAS_SERIAL_384_LEN;
extern const uint8_t RIOT_CORE_ALIAS_SERIAL_521[];
extern const size_t RIOT_CORE_ALIAS_SERIAL_521_LEN;

extern const char RIOT_CORE_ALIAS_NAME[];
extern const size_t RIOT_CORE_ALIAS_NAME_LEN;
extern const char RIOT_CORE_ALIAS_NAME_384[];
extern const size_t RIOT_CORE_ALIAS_NAME_384_LEN;
extern const char RIOT_CORE_ALIAS_NAME_521[];
extern const size_t RIOT_CORE_ALIAS_NAME_521_LEN;
extern const char RIOT_CORE_ALIAS_NAME_521_TRUNCATED[];
extern const size_t RIOT_CORE_ALIAS_NAME_521_TRUNCATED_LEN;

extern const uint8_t RIOT_CORE_ALIAS_CERT[];
extern const size_t RIOT_CORE_ALIAS_CERT_LEN;
extern const uint8_t RIOT_CORE_ALIAS_CERT_384[];
extern const size_t RIOT_CORE_ALIAS_CERT_384_LEN;
extern const uint8_t RIOT_CORE_ALIAS_CERT_521[];
extern const size_t RIOT_CORE_ALIAS_CERT_521_LEN;


#endif	/* RIOT_CORE_TESTING_H_ */
