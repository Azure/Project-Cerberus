// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KAT_H_
#define AES_KAT_H_

#include "crypto/aes_cbc.h"
#include "crypto/aes_ecb.h"
#include "crypto/aes_gcm.h"
#include "crypto/aes_xts.h"


int aes_cbc_kat_run_self_test_encrypt_aes256 (const struct aes_cbc_engine *aes);
int aes_cbc_kat_run_self_test_decrypt_aes256 (const struct aes_cbc_engine *aes);

int aes_ecb_kat_run_self_test_encrypt_aes256 (const struct aes_ecb_engine *aes);
int aes_ecb_kat_run_self_test_decrypt_aes256 (const struct aes_ecb_engine *aes);

int aes_gcm_kat_run_self_test_encrypt_aes256 (const struct aes_gcm_engine *aes);
int aes_gcm_kat_run_self_test_decrypt_aes256 (const struct aes_gcm_engine *aes);

int aes_xts_kat_run_self_test_encrypt_aes256 (const struct aes_xts_engine *aes);
int aes_xts_kat_run_self_test_decrypt_aes256 (const struct aes_xts_engine *aes);


#endif	/* AES_KAT_H_ */
