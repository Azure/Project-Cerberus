# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	GccRiscV32.cmake
#
# Abstract:
#
#	GCC RISC-V 32-bit Toolchain file
#
# --

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR riscv32)

set(CERBERUS_MCU_FLAGS -march=rv32imac)							# arch = rv32imac - 32 bit ISA with integer, machine, atomic and compressed
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mabi=ilp32")		# abi = ilp32 - int, long & pointers are 32bit, char=8bit, short=16bit, long long = 64bit
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mno-relax")		# no riscv linker relax support

set(CERBERUS_MCU_LINK_FLAGS -march=rv32imac)
set(CERBERUS_MCU_LINK_FLAGS "${CERBERUS_MCU_LINK_FLAGS} -mabi=ilp32")

if(DEFINED RISCV32_UNKNOWN_ELF)
	if(NOT TOOLCHAIN_PREFIX)
		set(TOOLCHAIN_PREFIX "riscv32-unknown-elf-")
	endif()

	include(${CMAKE_CURRENT_LIST_DIR}/Gcc.cmake)
else()
	include(${CMAKE_CURRENT_LIST_DIR}/GccRiscV64UnknownElf.cmake)
endif()
