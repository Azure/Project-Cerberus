// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_RMA_H_
#define CMD_INTERFACE_RMA_H_

#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/device_manager.h"


/**
 * A minimal command handler for supporting RMA processing.  Only commands explicitly needed in the
 * RMA context will be supported.
 */
struct cmd_interface_rma {
	struct cmd_interface base;						/**< Base command handler instance.  */
	struct device_manager *device_manager;			/**< Device manager instance */
};


int cmd_interface_rma_init (struct cmd_interface_rma *intf, struct device_manager *device_manager);
void cmd_interface_rma_release (const struct cmd_interface_rma *intf);


#endif /* CMD_INTERFACE_RMA_H_ */
