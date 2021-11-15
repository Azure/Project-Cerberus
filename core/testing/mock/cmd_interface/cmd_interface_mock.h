// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_MOCK_H_
#define CMD_INTERFACE_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "cmd_interface/cmd_interface.h"
#include "mock.h"


/**
 * Command Interface API mock
 */
struct cmd_interface_mock {
	struct cmd_interface base;		/**< Command interface instance*/
	struct mock mock;				/**< Mock instance*/
};

int cmd_interface_mock_init (struct cmd_interface_mock *mock);
void cmd_interface_mock_release (struct cmd_interface_mock *mock);

int cmd_interface_mock_validate_and_release (struct cmd_interface_mock *mock);

int cmd_interface_mock_validate_request (const char *arg_info, void *expected, void *actual);
void cmd_interface_mock_save_request (const struct mock_arg *expected, struct mock_arg *call);
void cmd_interface_mock_free_request (void *arg);
void cmd_interface_mock_copy_request (const struct mock_arg *expected, struct mock_arg *call,
	size_t out_len);
int cmd_interface_mock_duplicate_request (const void *arg_data, size_t arg_length, void **arg_save);


#endif /* CMD_INTERFACE_MOCK_H_ */
