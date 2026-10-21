// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_processor_mock.h"


static int host_processor_mock_power_on_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_power_on_reset, host, MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_PTR_CALL (rsa));
}

static int host_processor_mock_soft_reset (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_soft_reset, host, MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_PTR_CALL (rsa));
}

static int host_processor_mock_run_time_verification (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_run_time_verification, host,
		MOCK_ARG_PTR_CALL (hash), MOCK_ARG_PTR_CALL (rsa));
}

static int host_processor_mock_flash_rollback (const struct host_processor *host,
	const struct hash_engine *hash, const struct rsa_engine *rsa, bool disable_bypass,
	bool no_reset)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_flash_rollback, host, MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_PTR_CALL (rsa), MOCK_ARG_CALL (disable_bypass), MOCK_ARG_CALL (no_reset));
}

static int host_processor_mock_recover_active_read_write_data (const struct host_processor *host)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_processor_mock_recover_active_read_write_data, host);
}

static int host_processor_mock_get_next_reset_verification_actions (
	const struct host_processor *host)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_processor_mock_get_next_reset_verification_actions,
		host);
}

static int host_processor_mock_needs_config_recovery (const struct host_processor *host)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_processor_mock_needs_config_recovery, host);
}

static int host_processor_mock_apply_recovery_image (const struct host_processor *host,
	bool no_reset)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_apply_recovery_image, host,
		MOCK_ARG_CALL (no_reset));
}

static int host_processor_mock_bypass_mode (const struct host_processor *host, bool swap_flash)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_bypass_mode, host, MOCK_ARG_CALL (swap_flash));
}

static int host_processor_mock_get_flash_config (const struct host_processor *host,
	spi_filter_flash_mode *mode, spi_filter_cs *current_ro, spi_filter_cs *next_ro,
	enum host_read_only_activation *apply_next_ro)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_get_flash_config, host, MOCK_ARG_PTR_CALL (mode),
		MOCK_ARG_PTR_CALL (current_ro), MOCK_ARG_PTR_CALL (next_ro),
		MOCK_ARG_PTR_CALL (apply_next_ro));
}

static int host_processor_mock_config_read_only_flash (const struct host_processor *host,
	const spi_filter_cs *current_ro, const spi_filter_cs *next_ro,
	const enum host_read_only_activation *apply_next_ro)
{
	struct host_processor_mock *mock = (struct host_processor_mock*) host;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_processor_mock_config_read_only_flash, host,
		MOCK_ARG_PTR_CALL (current_ro), MOCK_ARG_PTR_CALL (next_ro),
		MOCK_ARG_PTR_CALL (apply_next_ro));
}

static int host_processor_mock_func_arg_count (void *func)
{
	if ((func == host_processor_mock_flash_rollback) ||
		(func == host_processor_mock_get_flash_config)) {
		return 4;
	}
	else if (func == host_processor_mock_config_read_only_flash) {
		return 3;
	}
	else if ((func == host_processor_mock_power_on_reset) ||
		(func == host_processor_mock_soft_reset) ||
		(func == host_processor_mock_run_time_verification)) {
		return 2;
	}
	else if ((func == host_processor_mock_apply_recovery_image) ||
		(func == host_processor_mock_bypass_mode)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* host_processor_mock_func_name_map (void *func)
{
	if (func == host_processor_mock_power_on_reset) {
		return "power_on_reset";
	}
	else if (func == host_processor_mock_soft_reset) {
		return "soft_reset";
	}
	else if (func == host_processor_mock_run_time_verification) {
		return "run_time_verification";
	}
	else if (func == host_processor_mock_flash_rollback) {
		return "flash_rollback";
	}
	else if (func == host_processor_mock_recover_active_read_write_data) {
		return "recover_active_read_write_data";
	}
	else if (func == host_processor_mock_get_next_reset_verification_actions) {
		return "get_next_reset_verification_actions";
	}
	else if (func == host_processor_mock_needs_config_recovery) {
		return "needs_config_recovery";
	}
	else if (func == host_processor_mock_apply_recovery_image) {
		return "apply_recovery_image";
	}
	else if (func == host_processor_mock_bypass_mode) {
		return "bypass_mode";
	}
	else if (func == host_processor_mock_get_flash_config) {
		return "get_flash_config";
	}
	else if (func == host_processor_mock_config_read_only_flash) {
		return "config_read_only_flash";
	}
	else {
		return "unknown";
	}
}

static const char* host_processor_mock_arg_name_map (void *func, int arg)
{
	if ((func == host_processor_mock_power_on_reset) || (func == host_processor_mock_soft_reset) ||
		(func == host_processor_mock_run_time_verification)) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "rsa";
		}
	}
	else if (func == host_processor_mock_flash_rollback) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "rsa";

			case 2:
				return "disable_bypass";

			case 3:
				return "no_reset";
		}
	}
	else if (func == host_processor_mock_apply_recovery_image) {
		switch (arg) {
			case 0:
				return "no_reset";
		}
	}
	else if (func == host_processor_mock_bypass_mode) {
		switch (arg) {
			case 0:
				return "swap_flash";
		}
	}
	else if (func == host_processor_mock_get_flash_config) {
		switch (arg) {
			case 0:
				return "mode";

			case 1:
				return "current_ro";

			case 2:
				return "next_ro";

			case 3:
				return "apply_next_ro";
		}
	}
	else if (func == host_processor_mock_config_read_only_flash) {
		switch (arg) {
			case 0:
				return "current_ro";

			case 1:
				return "next_ro";

			case 2:
				return "apply_next_ro";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock interface for host processor actions.
 *
 * @param mock The host processor mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int host_processor_mock_init (struct host_processor_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_processor_mock));

	status = host_processor_init (&mock->base, &mock->state);
	if (status != 0) {
		return status;
	}

	status = mock_init (&mock->mock);
	if (status != 0) {
		host_processor_release (&mock->base);

		return status;
	}

	mock_set_name (&mock->mock, "host_processor");

	mock->base.power_on_reset = host_processor_mock_power_on_reset;
	mock->base.soft_reset = host_processor_mock_soft_reset;
	mock->base.run_time_verification = host_processor_mock_run_time_verification;
	mock->base.flash_rollback = host_processor_mock_flash_rollback;
	mock->base.recover_active_read_write_data = host_processor_mock_recover_active_read_write_data;
	mock->base.get_next_reset_verification_actions =
		host_processor_mock_get_next_reset_verification_actions;
	mock->base.needs_config_recovery = host_processor_mock_needs_config_recovery;
	mock->base.apply_recovery_image = host_processor_mock_apply_recovery_image;
	mock->base.bypass_mode = host_processor_mock_bypass_mode;
	mock->base.get_flash_config = host_processor_mock_get_flash_config;
	mock->base.config_read_only_flash = host_processor_mock_config_read_only_flash;

	mock->mock.func_arg_count = host_processor_mock_func_arg_count;
	mock->mock.func_name_map = host_processor_mock_func_name_map;
	mock->mock.arg_name_map = host_processor_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a host processor mock.
 *
 * @param mock The mock to release.
 */
void host_processor_mock_release (struct host_processor_mock *mock)
{
	if (mock != NULL) {
		host_processor_release (&mock->base);
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int host_processor_mock_validate_and_release (struct host_processor_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_processor_mock_release (mock);
	}

	return status;
}
