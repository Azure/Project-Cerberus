// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_KEY_MANAGER_STATIC_H_
#define RIOT_KEY_MANAGER_STATIC_H_

#include "riot_key_manager.h"


/**
 * Initialize a static instance for managing DICE device identity keys.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the identity key manager.
 * @param keystore_ptr The storage to use for identity certificates.
 * @param x509_ptr The X.509 engine to use for certificate operations.
 * @param extra_csr_ptr Optional list of CSRs (or other binary data) that can be exported by the
 * device.  The CSRs in this list will be accessible starting with CSR command index 1, since 0 is
 * for the Device ID CSR.
 * @param csr_count_arg The number of extra CSRs in the list.
 */
#define	riot_key_manager_static_init(state_ptr, keystore_ptr, x509_ptr, extra_csr_ptr, \
	csr_count_arg)	{ \
		.state = state_ptr, \
		.keystore = keystore_ptr, \
		.x509 = x509_ptr, \
		.extra_csr = extra_csr_ptr, \
		.csr_count = csr_count_arg, \
	}


#endif	/* RIOT_KEY_MANAGER_STATIC_H_ */
