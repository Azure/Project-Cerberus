// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUX_ATTESTATION_TESTING_H_
#define AUX_ATTESTATION_TESTING_H_

#include <stdint.h>


extern const uint8_t KEY_SEED[];
extern const size_t KEY_SEED_LEN;
extern const uint8_t KEY_SEED_ENCRYPT_OAEP[];
extern const size_t KEY_SEED_ENCRYPT_OAEP_LEN;
extern const uint8_t KEY_SEED_ENCRYPT_OAEP_SHA256[];
extern const size_t KEY_SEED_ENCRYPT_OAEP_SHA256_LEN;
extern const uint8_t KEY_SEED_HASH[];
extern const size_t KEY_SEED_HASH_LEN;
extern const uint8_t NIST_KEY_DERIVE_I[];
extern const size_t NIST_KEY_DERIVE_I_LEN;
extern const uint8_t NIST_KEY_DERIVE_L[];
extern const size_t NIST_KEY_DERIVE_L_LEN;
extern const uint8_t SIGNING_KEY[];
extern const size_t SIGNING_KEY_LEN;
extern const uint8_t ENCRYPTION_KEY[];
extern const size_t ENCRYPTION_KEY_LEN;
extern const uint8_t CIPHER_TEXT[];
extern const size_t CIPHER_TEXT_LEN;
extern const uint8_t SEALING_POLICY[][64];
extern const size_t SEALING_POLICY_LEN;
extern const uint8_t PAYLOAD_HMAC[];
extern const size_t PAYLOAD_HMAC_LEN;
extern const uint8_t SEALING_POLICY_MULTIPLE[][64];
extern const size_t SEALING_POLICY_MULTPLE_LEN;
extern const uint8_t PAYLOAD_MULTIPLE_HMAC[];
extern const size_t PAYLOAD_MULTIPLE_HMAC_LEN;
extern const char ENCRYPTION_KEY_LABEL[];
extern const size_t ENCRYPTION_KEY_LABEL_LEN;
extern const char SIGNING_KEY_LABEL[];
extern const size_t SIGNING_KEY_LABEL_LEN;
extern const uint8_t PCR0_VALUE[];
extern const size_t PCR0_VALUE_LEN;


#endif /* AUX_ATTESTATION_TESTING_H_ */
