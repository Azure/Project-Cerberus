// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KEY_WRAP_KAT_H_
#define AES_KEY_WRAP_KAT_H_

#include "crypto/aes_key_wrap_interface.h"


int aes_key_wrap_kat_run_self_test_wrap_aes256 (const struct aes_key_wrap_interface *aes_kw);
int aes_key_wrap_kat_run_self_test_unwrap_aes256 (const struct aes_key_wrap_interface *aes_kw);

int aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (
	const struct aes_key_wrap_interface *aes_kwp);
int aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (
	const struct aes_key_wrap_interface *aes_kwp);


#endif	/* AES_KEY_WRAP_KAT_H_ */
