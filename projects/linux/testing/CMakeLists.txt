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
#	CMake script to build Cerberus Core & Platform Unit Tests
#
# --

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(cerberus-linux-unit-tests LANGUAGES C ASM)

include (${CMAKE_CURRENT_LIST_DIR}/../../../Cerberus.cmake)
include(Mbedtls)

set(CORE_DIR ${CERBERUS_ROOT}/core)
set(TESTING_DIR ${CERBERUS_ROOT}/testing)
set(PLATFORM_DIR ${CERBERUS_ROOT}/projects/linux)

file(GLOB_RECURSE CORE_SOURCES "${CORE_DIR}/*.c")
set(CORE_INCLUDES ${CORE_DIR})

file(GLOB_RECURSE PLATFORM_SOURCES "${PLATFORM_DIR}/*.c")
set(PLATFORM_INCLUDES ${PLATFORM_DIR})

file(GLOB_RECURSE TESTING_SOURCES "${TESTING_DIR}/*.c")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

set(TARGET_NAME ${PROJECT_NAME})

add_executable(
	${TARGET_NAME}
	${MBEDTLS_SOURCES}
	${CORE_SOURCES}
	${TESTING_SOURCES}
	${PLATFORM_SOURCES}
	)

target_include_directories(
	${TARGET_NAME}
	PRIVATE
		${MBEDTLS_INCLUDES}
		${CORE_INCLUDES}
		${PLATFORM_INCLUDES}
		${TESTING_DIR}
		${PLATFORM_INCLUDES}/testing/config
	)

target_compile_options(
	${TARGET_NAME}
	PRIVATE
 		-fno-builtin
		-fdata-sections
		-Wall
		-Wextra
 		-Werror
		-Wno-unused-parameter
		-g -ggdb3
	)

target_compile_definitions(
	${TARGET_NAME}
	PRIVATE
		ATTESTATION_SUPPORT_ECDH_UNSEAL
		ATTESTATION_SUPPORT_RSA_UNSEAL
		ATTESTATION_SUPPORT_RSA_CHALLENGE
		CMD_ENABLE_DEBUG_LOG
		CMD_ENABLE_HEAP_STATS
		CMD_ENABLE_RESET_CONFIG
		CMD_ENABLE_UNSEAL
		CMD_SUPPORT_DEBUG_COMMANDS
		CMD_SUPPORT_ENCRYPTED_SESSIONS
		ECC_ENABLE_GENERATE_KEY_PAIR
		ECC_ENABLE_ECDH
		FLASH_STORE_SUPPORT_NO_PARTIAL_PAGE_WRITE
		HASH_ENABLE_SHA1
		HASH_ENABLE_SHA384
		HASH_ENABLE_SHA512
		RSA_ENABLE_DER_PUBLIC_KEY
		RSA_ENABLE_PRIVATE_KEY
		X509_ENABLE_CREATE_CERTIFICATES
		X509_ENABLE_AUTHENTICATION
	)

target_link_libraries(
	${TARGET_NAME}
	PRIVATE
		Threads::Threads
		OpenSSL::Crypto
		m
	)
