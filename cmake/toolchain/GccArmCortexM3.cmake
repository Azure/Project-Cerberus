# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	GccArmCortexM3.cmake
#
# Abstract:
#
#	GCC ARM Cortex-M3 Toolchain file
#
# --

set(CMAKE_SYSTEM_NAME Generic)
SET(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR Cortex-M3)

set(CERBERUS_MCU_FLAGS "-mcpu=cortex-m3")
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mthumb")

include(${CMAKE_CURRENT_LIST_DIR}/GccArmNoneEabi.cmake)
