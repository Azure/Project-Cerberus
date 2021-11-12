# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	GccRiscV64UnknownElf.cmake
#
# Abstract:
#
#	GCC RISC-V multilib Embedded toolchain settings.
#
# --

#
# Set the toolchain prefix.
#
if(NOT TOOLCHAIN_PREFIX)
	set(TOOLCHAIN_PREFIX "riscv64-unknown-elf-")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/Gcc.cmake)
