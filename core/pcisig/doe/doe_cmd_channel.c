// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "cmd_interface/cmd_interface.h"
#include "doe_cmd_channel.h"


/**
 * Receive a single message from a DOE communication channel and process it.
 *
 * @param channel The channel to receive a message from.
 * @param doe The DOE interface to use for processing the received message.
 * @param ms_timeout The amount of time to wait to receive a message, in milliseconds.
 * A negative value will wait forever, and a value of 0 will return immediately.
 *
 * @return 0 if a message was processed successfully or an error code.
 */
int doe_cmd_channel_receive_and_process (const struct doe_cmd_channel *channel,
	const struct doe_interface *doe, int ms_timeout)
{
	int status = 0;
	struct doe_cmd_message *doe_message;

	if ((channel == NULL) || (doe == NULL)) {
		status = DOE_CMD_CHANNEL_INVALID_ARGUMENT;
		goto exit;
	}

	status = channel->receive_message (channel, &doe_message, ms_timeout);
	if (status != 0) {
		goto exit;
	}

	status = doe_interface_process_message (doe, doe_message);
	if (status != 0) {
		goto exit;
	}

	status = channel->send_message (channel, doe_message);
	if (status != 0) {
		goto exit;
	}

exit:
	return status;
}