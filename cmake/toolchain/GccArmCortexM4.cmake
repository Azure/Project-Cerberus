# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	GccArmCortexM4.cmake
#
# Abstract:
#
#	GCC ARM Cortex-M4 Toolchain file
#
# --

set(CMAKE_SYSTEM_NAME Generic)
SET(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR Cortex-M4)

set(CERBERUS_MCU_FLAGS "-mcpu=cortex-m4")
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mfloat-abi=hard")
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mfpu=fpv4-sp-d16")

include(${CMAKE_CURRENT_LIST_DIR}/GccArmNoneEabi.cmake)
