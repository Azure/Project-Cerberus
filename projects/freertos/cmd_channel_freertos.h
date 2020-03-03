// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_FREERTOS_H_
#define CMD_CHANNEL_FREERTOS_H_

#include "FreeRTOS.h"
#include "queue.h"
#include "cmd_interface/cmd_channel.h"


int cmd_channel_freertos_receive_packet (QueueHandle_t rx_queue, struct cmd_packet *packet,
	int ms_timeout);
int cmd_channel_freertos_send_packet (QueueHandle_t tx_queue, struct cmd_packet *packet,
	int ms_timeout);


#endif /* CMD_CHANNEL_FREERTOS_H_ */
