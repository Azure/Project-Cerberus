# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	CMakeLists.txt
#
# Abstract:
#
#	CMake script to build a test utility for executing unseal flows.
#
# --

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(unseal LANGUAGES C ASM)

set(TARGET_NAME ${PROJECT_NAME})

include (${CMAKE_CURRENT_LIST_DIR}/../../../Cerberus.cmake)
include(Mbedtls)

set(CORE_DIR ${CERBERUS_ROOT}/core)
set(PLATFORM_DIR ${CERBERUS_ROOT}/projects/linux)
set(UNSEAL_DIR ${CERBERUS_ROOT}/tools/testing/unseal)

find_package(Threads REQUIRED)


add_executable(
	${TARGET_NAME}
	${MBEDTLS_SOURCES}
	${CORE_DIR}/asn1/asn1_util.c
	${CORE_DIR}/asn1/ecc_der_util.c
	${CORE_DIR}/asn1/x509_mbedtls.c
	${CORE_DIR}/attestation/aux_attestation.c
	${CORE_DIR}/attestation/pcr.c
	${CORE_DIR}/attestation/pcr_store.c
	${CORE_DIR}/common/buffer_util.c
	${CORE_DIR}/crypto/ecc_mbedtls.c
	${CORE_DIR}/crypto/hash_mbedtls.c
	${CORE_DIR}/crypto/hash.c
	${CORE_DIR}/crypto/kdf.c
	${CORE_DIR}/logging/debug_log.c
	${CORE_DIR}/keystore/keystore_null.c
	${CORE_DIR}/riot/riot_key_manager.c
	${PLATFORM_DIR}/platform.c
	${UNSEAL_DIR}/unseal.c
	)

target_include_directories(
	${TARGET_NAME}
	PRIVATE
		${MBEDTLS_INCLUDES}
		${CORE_DIR}
		${PLATFORM_DIR}
	)

target_compile_options(
	${TARGET_NAME}
	PRIVATE
 		-fno-builtin
		-fdata-sections
		-Wall
		-Wextra
 		-Werror
		-g -ggdb3
	)

target_compile_definitions(
	${TARGET_NAME}
	PRIVATE
		ATTESTATION_SUPPORT_ECDH_UNSEAL
		ECC_ENABLE_ECDH
		HASH_ENABLE_SHA1
		HASH_ENABLE_SHA384
		HASH_ENABLE_SHA512
		X509_ENABLE_AUTHENTICATION
	)

target_link_libraries(
	${TARGET_NAME}
	PRIVATE
		Threads::Threads
		m
	)
