// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OCP_RECOVERY_DEVICE_VARIABLE_CMS_MOCK_H_
#define OCP_RECOVERY_DEVICE_VARIABLE_CMS_MOCK_H_

#include "recovery/ocp_recovery_device.h"
#include "mock.h"


/**
 * A mock for a OCP Recovery device handler variable CMS interface.
 */
struct ocp_recovery_device_variable_cms_mock {
	struct ocp_recovery_device_variable_cms base;	/**< The base CMS instance. */
	struct mock mock;								/**< The base mock interface. */
};


int ocp_recovery_device_variable_cms_mock_init (
	struct ocp_recovery_device_variable_cms_mock *mock);
void ocp_recovery_device_variable_cms_mock_release (
	struct ocp_recovery_device_variable_cms_mock *mock);

int ocp_recovery_device_variable_cms_mock_validate_and_release (
	struct ocp_recovery_device_variable_cms_mock *mock);


#endif /* OCP_RECOVERY_DEVICE_VARIABLE_CMS_MOCK_H_ */
