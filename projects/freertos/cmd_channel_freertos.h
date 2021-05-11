// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_CHANNEL_FREERTOS_H_
#define CMD_CHANNEL_FREERTOS_H_

#include "FreeRTOS.h"
#include "queue.h"
#include "cmd_interface/cmd_channel.h"

extern QueueHandle_t I2CRequestQueue;
extern QueueHandle_t I2CResponseQueue;

int cmd_channel_freertos_receive_packet (QueueHandle_t rx_queue, struct cmd_packet *packet,
	int ms_timeout);
int cmd_channel_freertos_send_packet (QueueHandle_t tx_queue, struct cmd_packet *packet,
	int ms_timeout);

void cmd_channel_packet_default_init (struct cmd_channel *channel);

#endif /* CMD_CHANNEL_FREERTOS_H_ */
