// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform.h"
#include "cmd_interface/cmd_authorization.h"
#include "testing/mock/common/authorization_mock.h"


TEST_SUITE_LABEL ("cmd_authorization");


/*******************
 * Test cases
 *******************/

static void authorization_allowed_test_init (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.authorize_revert_bypass);
	CuAssertPtrNotNull (test, auth.authorize_reset_defaults);
	CuAssertPtrNotNull (test, auth.authorize_clear_platform_config);
	CuAssertPtrNotNull (test, auth.authorize_reset_intrusion);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_init_null (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	int status;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (NULL, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);
}

static void authorization_allowed_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_authorization_release (NULL);
}

static void authorization_allowed_test_authorize_revert_bypass (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&bypass.mock, bypass.base.authorize, &bypass, 0, MOCK_ARG (&nonce),
		MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_revert_bypass (&auth, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_revert_bypass_no_authorization (CuTest *test)
{
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, NULL, &defaults.base, &platform.base, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_revert_bypass (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_revert_bypass_challenge (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&bypass.mock, bypass.base.authorize, &bypass, AUTHORIZATION_CHALLENGE,
		MOCK_ARG (&nonce), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_revert_bypass (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_revert_bypass_null (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_revert_bypass (NULL, &nonce, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_defaults (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&defaults.mock, defaults.base.authorize, &defaults, 0, MOCK_ARG (&nonce),
		MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_defaults (&auth, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_defaults_no_authorization (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, NULL, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_defaults (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_defaults_challenge (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&defaults.mock, defaults.base.authorize, &defaults,
		AUTHORIZATION_CHALLENGE, MOCK_ARG (&nonce), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_defaults (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_defaults_null (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_defaults (NULL, &nonce, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_clear_platform_config (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&platform.mock, platform.base.authorize, &platform, 0, MOCK_ARG (&nonce),
		MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_clear_platform_config (&auth, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_clear_platform_config_no_authorization (
	CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, NULL, &intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_clear_platform_config (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_clear_platform_config_challenge (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&platform.mock, platform.base.authorize, &platform,
		AUTHORIZATION_CHALLENGE, MOCK_ARG (&nonce), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_clear_platform_config (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_clear_platform_config_null (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_clear_platform_config (NULL, &nonce, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_intrusion (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&intrusion.mock, intrusion.base.authorize, &intrusion, 0, MOCK_ARG (&nonce),
		MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_intrusion (&auth, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_intrusion_no_authorization (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_intrusion (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_intrusion_challenge (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&intrusion.mock, intrusion.base.authorize, &intrusion,
		AUTHORIZATION_CHALLENGE, MOCK_ARG (&nonce), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_intrusion (&auth, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}

static void authorization_allowed_test_authorize_reset_intrusion_null (CuTest *test)
{
	struct authorization_mock bypass;
	struct authorization_mock defaults;
	struct authorization_mock platform;
	struct authorization_mock intrusion;
	struct cmd_authorization auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = authorization_mock_init (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_init (&intrusion);
	CuAssertIntEquals (test, 0, status);

	status = cmd_authorization_init (&auth, &bypass.base, &defaults.base, &platform.base,
		&intrusion.base);
	CuAssertIntEquals (test, 0, status);

	status = auth.authorize_reset_intrusion (NULL, &nonce, &length);
	CuAssertIntEquals (test, CMD_AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_mock_validate_and_release (&bypass);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&defaults);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&platform);
	CuAssertIntEquals (test, 0, status);

	status = authorization_mock_validate_and_release (&intrusion);
	CuAssertIntEquals (test, 0, status);

	cmd_authorization_release (&auth);
}


TEST_SUITE_START (cmd_authorization);

TEST (authorization_allowed_test_init);
TEST (authorization_allowed_test_init_null);
TEST (authorization_allowed_test_release_null);
TEST (authorization_allowed_test_authorize_revert_bypass);
TEST (authorization_allowed_test_authorize_revert_bypass_no_authorization);
TEST (authorization_allowed_test_authorize_revert_bypass_challenge);
TEST (authorization_allowed_test_authorize_revert_bypass_null);
TEST (authorization_allowed_test_authorize_reset_defaults);
TEST (authorization_allowed_test_authorize_reset_defaults_no_authorization);
TEST (authorization_allowed_test_authorize_reset_defaults_challenge);
TEST (authorization_allowed_test_authorize_reset_defaults_null);
TEST (authorization_allowed_test_authorize_clear_platform_config);
TEST (authorization_allowed_test_authorize_clear_platform_config_no_authorization);
TEST (authorization_allowed_test_authorize_clear_platform_config_challenge);
TEST (authorization_allowed_test_authorize_clear_platform_config_null);
TEST (authorization_allowed_test_authorize_reset_intrusion);
TEST (authorization_allowed_test_authorize_reset_intrusion_no_authorization);
TEST (authorization_allowed_test_authorize_reset_intrusion_challenge);
TEST (authorization_allowed_test_authorize_reset_intrusion_null);

TEST_SUITE_END;
