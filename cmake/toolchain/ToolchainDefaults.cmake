# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	ToolchainDefaults.cmake
#
# Abstract:
#
#	CMake script to set the toolchain defaults
#
# --

#
# Set the default build type
#
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release")
endif()

#
# Check the build type is valid (i.e. Release or Debug)
#
string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_LOWER)
if(NOT ${BUILD_TYPE_LOWER} STREQUAL "debug" AND NOT ${BUILD_TYPE_LOWER} STREQUAL "release")
	message(FATAL_ERROR "Unknown build type '${CMAKE_BUILD_TYPE}'. Allowed build types \
		debug or release")
endif()
