// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_MOCK_H_
#define MANIFEST_CMD_HANDLER_MOCK_H_

#include "mock.h"
#include "manifest/manifest_cmd_handler.h"


/**
 * A mock for a handler of manifest operations.
 */
struct manifest_cmd_handler_mock {
	struct manifest_cmd_handler base;	/**< The base manifest handler instance. */
	struct mock mock;					/**< The base mock instance. */
};


int manifest_cmd_handler_mock_init (struct manifest_cmd_handler_mock *mock,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task);
void manifest_cmd_handler_mock_release (struct manifest_cmd_handler_mock *mock);

int manifest_cmd_handler_mock_validate_and_release (struct manifest_cmd_handler_mock *mock);

int manifest_cmd_handler_mock_activation (const struct manifest_cmd_handler *handler, bool *reset);
void manifest_cmd_handler_mock_enable_activation (struct manifest_cmd_handler_mock *mock);


#endif	/* MANIFEST_CMD_HANDLER_MOCK_H_ */
