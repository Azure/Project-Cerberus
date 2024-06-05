// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_INTERMEDIATE_H_
#define MSG_TRANSPORT_INTERMEDIATE_H_

#include <stdint.h>
#include "cmd_interface/msg_transport.h"
#include "mctp/cmd_interface_protocol_mctp.h"


/**
 * Defines an intermediate layer of the protocol stack for sending request messages.  This transport
 * does not directly transmit messages to another entity.  It will apply protocol specific
 * processing to outgoing requests before passing it on to the next layer of the stack.  Likewise,
 * it will process incoming responses before returning them to the originator of the request.
 *
 * Each intermediate layer implemented in this way must apply a constant amount of overhead to each
 * message, regardless of payload size or type.
 *
 * This is not a complete implementation that can be instantiated on it's own.  It is meant to serve
 * as a base type for implementing specific protocol handlers.
 */
struct msg_transport_intermediate {
	struct msg_transport base;			/**< Base transport API for this layer. */
	const struct msg_transport *next;	/**< Interface to next transport in the protocol stack. */
	size_t msg_overhead;				/**< Number of overhead bytes added to each message. */
};


/* Internal functions for use by derived types. */
int msg_transport_intermediate_init (struct msg_transport_intermediate *intermediate,
	const struct msg_transport *next_transport, size_t msg_overhead);
void msg_transport_intermediate_release (const struct msg_transport_intermediate *intermediate);


#endif /* MSG_TRANSPORT_INTERMEDIATE_H_ */
