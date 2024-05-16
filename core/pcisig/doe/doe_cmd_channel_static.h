// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DOE_CMD_CHANNEL_STATIC_H_
#define DOE_CMD_CHANNEL_STATIC_H_


/* Static initializer API for derived types. */

/**
 * Initialize a static instance of a base doe command channel context.  This is not a top level API
 * and must only be called by an implementation API.
 *
 * There is no validation done on the arguments.
 *
 * @param recv_func The doe command channel message receive handler.
 * @param send_func The doe command channel message send handler.
 */
#define doe_cmd_channel_static_init(recv_func, send_func) { \
		.receive_message = recv_func, \
		.send_message = send_func, \
	}


#endif	/* DOE_CMD_CHANNEL_STATIC_H_ */
