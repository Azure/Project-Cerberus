// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_CORE_TESTING_H_
#define RIOT_CORE_TESTING_H_

#include <stdint.h>
#include <stddef.h>


extern const uint8_t RIOT_CORE_CDI[];
extern const size_t RIOT_CORE_CDI_LEN;

extern const uint8_t RIOT_CORE_CDI_HASH[];
extern const size_t RIOT_CORE_CDI_HASH_LEN;

extern const uint8_t RIOT_CORE_SERIAL_KDF_DATA[];
extern const size_t RIOT_CORE_SERIAL_KDF_DATA_LEN;

extern const size_t RIOT_CORE_SERIAL_LEN;

extern const uint8_t RIOT_CORE_DEVICE_ID[];
extern const size_t RIOT_CORE_DEVICE_ID_LEN;

extern const uint8_t RIOT_CORE_DEVID_SERIAL[];
extern const size_t RIOT_CORE_DEVID_SERIAL_LEN;

extern const char RIOT_CORE_DEVID_NAME[];
extern const size_t RIOT_CORE_DEVID_NAME_LEN;

extern const uint8_t RIOT_CORE_DEVID_CSR[];
extern const size_t RIOT_CORE_DEVID_CSR_LEN;

extern const uint8_t RIOT_CORE_DEVID_CERT[];
extern const size_t RIOT_CORE_DEVID_CERT_LEN;

extern const uint8_t RIOT_CORE_DEVID_SIGNED_CERT[];
extern const size_t RIOT_CORE_DEVID_SIGNED_CERT_LEN;

extern const uint8_t RIOT_CORE_DEVID_INTR_SIGNED_CERT[];
extern const size_t RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;

extern const char *RIOT_CORE_ALIAS_VERSION;
extern const uint32_t RIOT_CORE_ALIAS_SVN;

extern const uint8_t RIOT_CORE_FWID[];
extern const size_t RIOT_CORE_FWID_LEN;

extern const uint8_t RIOT_CORE_FWID_KDF[];
extern const size_t RIOT_CORE_FWID_KDF_LEN;

extern const uint8_t RIOT_CORE_ALIAS_KEY[];
extern const size_t RIOT_CORE_ALIAS_KEY_LEN;

extern const uint8_t RIOT_CORE_ALIAS_SERIAL[];
extern const size_t RIOT_CORE_ALIAS_SERIAL_LEN;

extern const char RIOT_CORE_ALIAS_NAME[];
extern const size_t RIOT_CORE_ALIAS_NAME_LEN;

extern const uint8_t RIOT_CORE_ALIAS_CERT[];
extern const size_t RIOT_CORE_ALIAS_CERT_LEN;


#endif /* RIOT_CORE_TESTING_H_ */
