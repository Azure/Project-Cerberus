// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_STATIC_H_
#define OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_STATIC_H_

#include "ocp_recovery_device_variable_cms_log.h"


/* Internal functions declared to allow for static initialization. */
int ocp_recovery_device_variable_cms_log_get_size (
	const struct ocp_recovery_device_variable_cms *cms);
int ocp_recovery_device_variable_cms_log_get_data (
	const struct ocp_recovery_device_variable_cms *cms, size_t offset, uint8_t *data,
	size_t length);


/**
 * Constant initializer for the variable CMS API.
 */
#define	OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_API_INIT  { \
		.get_size = ocp_recovery_device_variable_cms_log_get_size, \
		.get_data = ocp_recovery_device_variable_cms_log_get_data, \
	}


/**
 * Initialize a static instance of a variable CMS log wrapper.
 *
 * There is no validation done on the arguments.
 *
 * @param log_ptr Interface to the log containing the CMS data.  This can be a constant instance.
 */
#define	ocp_recovery_device_variable_cms_log_static_init(log_ptr)	{ \
		.base = OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_API_INIT, \
		.log = log_ptr, \
	}


#endif /* OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_STATIC_H_ */
