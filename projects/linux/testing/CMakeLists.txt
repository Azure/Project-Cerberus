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

set(TARGET_NAME ${PROJECT_NAME})

include (${CMAKE_CURRENT_LIST_DIR}/../../../Cerberus.cmake)
include(Mbedtls)
include(AllFeatures)
include(Coverage)

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
		${CERBERUS_ALL_FEATURES}
	)

target_link_libraries(
	${TARGET_NAME}
	PRIVATE
		Threads::Threads
		OpenSSL::Crypto
		m
	)

SETUP_TARGET_FOR_COVERAGE(
	NAME coverage
 	EXECUTABLE ${PROJECT_NAME}
 	DEPENDENCIES ${PROJECT_NAME}
	)
