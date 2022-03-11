// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_H_
#define OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_H_

#include "ocp_recovery_device.h"
#include "logging/logging.h"


/**
 * A variable CMS interface that uses a logging interface to retrieve the CMS data.
 */
struct ocp_recovery_device_variable_cms_log {
	struct ocp_recovery_device_variable_cms base;		/**< The base CMS interface. */
	struct logging *log;								/**< Logging interface for the data. */
};


int ocp_recovery_device_variable_cms_log_init (struct ocp_recovery_device_variable_cms_log *cms,
	struct logging *log);
void ocp_recovery_device_variable_cms_log_release (
	const struct ocp_recovery_device_variable_cms_log *cms);


#endif /* OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_H_ */
