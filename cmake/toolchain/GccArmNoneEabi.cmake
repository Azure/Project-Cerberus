# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	GccArmNoneEabi.cmake
#
# Abstract:
#
#	GCC ARM Embedded toolchain settings.
#
# --

#
# Set the toolchain prefix.
#
if(NOT TOOLCHAIN_PREFIX)
	set(TOOLCHAIN_PREFIX "arm-none-eabi-")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/Gcc.cmake)
