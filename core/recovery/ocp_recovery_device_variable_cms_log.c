// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ocp_recovery_device_variable_cms_log.h"
#include "common/unused.h"


int ocp_recovery_device_variable_cms_log_get_size (
	const struct ocp_recovery_device_variable_cms *cms)
{
	const struct ocp_recovery_device_variable_cms_log *log =
		(const struct ocp_recovery_device_variable_cms_log*) cms;

	if (log == NULL) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	return log->log->get_size (log->log);
}

int ocp_recovery_device_variable_cms_log_get_data (
	const struct ocp_recovery_device_variable_cms *cms, size_t offset, uint8_t *data, size_t length)
{
	const struct ocp_recovery_device_variable_cms_log *log =
		(const struct ocp_recovery_device_variable_cms_log*) cms;

	if (log == NULL) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	return log->log->read_contents (log->log, offset, data, length);
}

/**
 * Initialize a log wrapper for a variable CMS.
 *
 * @param cms The CMS interface to initialize.
 * @param log The log that contains the data for the CMS.
 *
 * @return 0 if the CMS log wrapper was initialized successfully or an error code.
 */
int ocp_recovery_device_variable_cms_log_init (struct ocp_recovery_device_variable_cms_log *cms,
	struct logging *log)
{
	if ((cms == NULL) || (log == NULL)) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	memset (cms, 0, sizeof (struct ocp_recovery_device_variable_cms_log));

	cms->base.get_size = ocp_recovery_device_variable_cms_log_get_size;
	cms->base.get_data = ocp_recovery_device_variable_cms_log_get_data;

	cms->log = log;

	return 0;
}

/**
 * Release the resources used for a variable CMS log wrapper.
 *
 * @param cms The CMS interface to release.
 */
void ocp_recovery_device_variable_cms_log_release (
	const struct ocp_recovery_device_variable_cms_log *cms)
{
	UNUSED (cms);
}
