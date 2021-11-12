# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	ClangRiscV32.cmake
#
# Abstract:
#
#	Clang RISC-V 32-bit Toolchain file
#
# --

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR riscv32)

set(CERBERUS_MCU_FLAGS --target=riscv32)						# target riscv32 architecture
set(CERBERUS_MCU_FLAGS ${CERBERUS_MCU_FLAGS} -march=rv32imac)	# arch = rv32imac - 32 bit ISA with integer, machine, atomic and compressed
set(CERBERUS_MCU_FLAGS ${CERBERUS_MCU_FLAGS} -mabi=ilp32)		# abi = ilp32 - int, long & pointers are 32bit, char=8bit, short=16bit, long long = 64bit
set(CERBERUS_MCU_FLAGS ${CERBERUS_MCU_FLAGS} -mno-relax)		# no riscv relax support https://reviews.llvm.org/D77694
#set(CERBERUS_MCU_FLAGS ${CERBERUS_MCU_FLAGS} -fuse-ld=lld)	# not supported on current version bug: https://reviews.llvm.org/D74704

set(CERBERUS_MCU_LINK_FLAGS -m elf32lriscv)

add_compile_definitions(PLATFORM_RISCV)
add_compile_definitions(LITTLEENDIAN_CPU)

include(${CMAKE_CURRENT_LIST_DIR}/Clang.cmake)

#
# Add target system root to cmake find path.
#
get_filename_component(RISCV_COMPILER_DIR "${CMAKE_C_COMPILER}" DIRECTORY)
get_filename_component(CMAKE_FIND_ROOT_PATH "${RISCV_COMPILER_DIR}" DIRECTORY)
