// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DOE_INTERFACE_STATIC_H_
#define DOE_INTERFACE_STATIC_H_


/**
 * DOE interface initialization
 *
 * There is no validation done on the arguments.
 *
 * @param spdm_responder_ptr The SPDM interface to use for processing and generating
 * SPDM protocol messages.
 */
#define	doe_interface_static_init(spdm_responder_ptr)	{ \
		.cmd_spdm_responder = spdm_responder_ptr, \
	}


#endif /* DOE_INTERFACE_STATIC_H_ */