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
#	GCC toolchain settings.
#
# --

include(${CMAKE_CURRENT_LIST_DIR}/ToolchainDefaults.cmake)

#
# CMake during config phase tests the compiler by compiling an executable. The following statement
# configures CMake to compile a static library instead.
#
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

#
# Register the toolchain with CMake.
#
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
set(CMAKE_OBJCOPY ${TOOLCHAIN_PREFIX}objcopy)
set(CMAKE_OBJDUMP ${TOOLCHAIN_PREFIX}objdump)
set(CMAKE_SIZE_UTIL ${TOOLCHAIN_PREFIX}size)

#
# Set the default compiler flags.
#
set(CERBERUS_C_FLAGS ${CERBERUS_MCU_FLAGS})
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -std=c11")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -fno-builtin")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -fdata-sections")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -ffunction-sections")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -Wall")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -Wextra")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -pedantic")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -Werror")
set(CERBERUS_C_FLAGS "${CERBERUS_C_FLAGS} -g -ggdb3")
set(CMAKE_C_FLAGS ${CERBERUS_C_FLAGS})

#
# Set the linker flags.
#
set(CERBERUS_LINKER_FLAGS ${CERBERUS_MCU_LINK_FLAGS})
set(CERBERUS_LINKER_FLAGS "${CERBERUS_LINKER_FLAGS} -Wl,--gc-sections")
set(CERBERUS_LINKER_FLAGS "${CERBERUS_LINKER_FLAGS} -specs=nano.specs")
set(CERBERUS_LINKER_FLAGS "${CERBERUS_LINKER_FLAGS} -specs=nosys.specs")
set(CERBERUS_LINKER_FLAGS "${CERBERUS_LINKER_FLAGS} -Wl,--fatal-warnings")
set(CMAKE_EXE_LINKER_FLAGS ${CERBERUS_LINKER_FLAGS})

#
# Search for programs in build host directories.
#
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

#
# Search for header and libs in toolchain folders.
#
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
