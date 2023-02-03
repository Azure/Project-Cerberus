# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	FreeRTOS.cmake
#
# Abstract:
#
#	CMake build script for FreeRTOS.
#  This script only defines build items common to ALL possible ports of
#  FreeRTOS.  Any port-specific items are defined in dedicated project directories.
#
# --
set(FREERTOS_COMMON_ROOT ${CERBERUS_ROOT}/external/freertos)
set(FREERTOS_PORTABLE_ROOT ${FREERTOS_COMMON_ROOT}/portable)

file(GLOB FREERTOS_SOURCES LIST_DIRECTORIES false ${FREERTOS_COMMON_ROOT}/*.c)

set(FREERTOS_INCLUDES ${FREERTOS_COMMON_ROOT}/include)