# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
#Module Name:
#
#	Mbedtls.cmake
#
# Abstract:
#
#	CMake build script for mbedtls.
#
# --

set(MBEDTLS_DIR ${CERBERUS_ROOT}/external/mbedtls-2.17.0)
file(GLOB MBEDTLS_SOURCES ${MBEDTLS_DIR}/library/*.c)
set(MBEDTLS_INCLUDES ${MBEDTLS_DIR}/include)

