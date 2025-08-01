# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
#Module Name:
#
#	AllFeatures.cmake
#
# Abstract:
#
#	Defines the full set of compiler definitions necessary to enable all features of the code.  This
#   is mostly useful for unit testing scenarios where everything needs to be enabled.
#
# --

set(
	CERBERUS_ALL_FEATURES
		ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
		ATTESTATION_SUPPORT_DEVICE_DISCOVERY
		ATTESTATION_SUPPORT_ECDH_UNSEAL
		ATTESTATION_SUPPORT_RSA_CHALLENGE
		ATTESTATION_SUPPORT_RSA_UNSEAL
		ATTESTATION_SUPPORT_SPDM
		CMD_ENABLE_DEBUG_LOG
		CMD_ENABLE_HEAP_STATS
		CMD_ENABLE_INTRUSION
		CMD_ENABLE_ISSUE_REQUEST
		CMD_ENABLE_RESET_CONFIG
		CMD_ENABLE_STACK_STATS
		CMD_ENABLE_UNSEAL
		CMD_SUPPORT_DEBUG_COMMANDS
		CMD_SUPPORT_ENCRYPTED_SESSIONS
		ECC_ENABLE_ECDH
		ECC_ENABLE_GENERATE_KEY_PAIR
		ECDH_ENABLE_FIPS_CMVP_TESTING
		ECDSA_ENABLE_FIPS_CMVP_TESTING
		FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
		HASH_ENABLE_SHA1
		HASH_ENABLE_SHA384
		HASH_ENABLE_SHA512
		LOGGING_SUPPORT_DEBUG_LOG
		RSA_ENABLE_DER_PUBLIC_KEY
		RSA_ENABLE_PRIVATE_KEY
		X509_ENABLE_AUTHENTICATION
		X509_ENABLE_CREATE_CERTIFICATES

		# This is an mbedTLS definition needed for unit tests to pass.
		MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
	)
