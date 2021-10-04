# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	Clang.cmake
#
# Abstract:
#
#	Clang Toolchain file
#
# --

include(${CMAKE_CURRENT_LIST_DIR}/ToolchainDefaults.cmake)

#
# Register the toolchain with CMake.
#
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}clang${TOOLCHAIN_VERSION})
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}clang++${TOOLCHAIN_VERSION})
set(CMAKE_AR ${TOOLCHAIN_PREFIX}llvm-ar${TOOLCHAIN_VERSION})
set(CMAKE_LINKER ${TOOLCHAIN_PREFIX}ld.lld${TOOLCHAIN_VERSION})
set(CMAKE_OBJCOPY ${TOOLCHAIN_PREFIX}llvm-objcopy${TOOLCHAIN_VERSION})
set(CMAKE_OBJDUMP ${TOOLCHAIN_PREFIX}llvm-objdump${TOOLCHAIN_VERSION})
set(CMAKE_SIZE_UTIL ${TOOLCHAIN_PREFIX}size${TOOLCHAIN_VERSION})

set(CLANG_FORMAT ${TOOLCHAIN_PREFIX}clang-format${TOOLCHAIN_VERSION})

#
# Set the default compiler flags.
# https://clang.llvm.org/docs/UsersManual.html#id9
#
add_compile_options(
	${CERBERUS_MCU_FLAGS}
	-std=c2x					# use c20 standard. Default is c17
	-c							# compile the file
	-fdata-sections				# which is really useful when we have to figure out what is in each region
	-fdiagnostics-color=always	# Show colorized output
	-ffunction-sections			# These switches puts the func/data in their own section
	-fno-common					# Do not put uninitialized section in COMMON, instead add it to bss
	-fstack-protector-all		# buffer overflow checks for all functions
	-g							# generate debugging information
	-Wall						# Enable all warnings
	-Wextra						# Enable extra warnings
	-Werror						# all warnings are errors
	)

#
# Use minimum optimization for debug configuration. For release the cmake specifies -O3
#
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O -DDEBUG")

#
# Set the default linker flags.
#
add_link_options(
	${CERBERUS_MCU_LINK_FLAGS}
	--gc-sections
	)

set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
set(CMAKE_CXX_LINK_EXECUTABLE "<CMAKE_LINKER> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

#
# Use LLVM lld linker
#
set(LLVM_ENABLE_PROJECTS lld)

#
# Disable compiler checks
#
set(CMAKE_C_COMPILER_FORCED TRUE)
set(CMAKE_CXX_COMPILER_FORCED TRUE)

#
# Don't look for executable in target system prefix.
#
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

#
# Look for includes and libraries only in the target system prefix.
#
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
