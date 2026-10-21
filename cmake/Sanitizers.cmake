# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	Sanitizers.cmake
#
# Abstract:
#
#   Sets up the sanitizers target for runnning unit tests
#
# --

# All these are supported by both clang and gcc
string(JOIN " " CERBERUS_SANITIZER_FLAGS
	-fno-omit-frame-pointer
	-fsanitize-recover=all
	-fsanitize=address
	-fsanitize=pointer-compare
	-fsanitize=pointer-subtract
	-fsanitize=leak
	-fsanitize=undefined
	-fsanitize-address-use-after-scope
)

string(JOIN ":" CERBERUS_ASAN_OPTIONS
	halt_on_error=0
)

string(JOIN ":" CERBERUS_UBSAN_OPTIONS
	print_stacktrace=1
	halt_on_error=0
)

# GCC doesn't support ignorelist
if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
	set (CERBERUS_SANITIZER_FLAGS "${CERBERUS_SANITIZER_FLAGS} -fsanitize-ignorelist=${CERBERUS_ROOT}/tools/sanitizers-ignorelist.txt")
endif()


# Introduces a separate build type "DebugWithSanitizers". 
# The coverage target will also be built with sanitizers if this build type is selected.
set(CMAKE_CXX_FLAGS_DEBUGWITHSANITIZERS "${CMAKE_CXX_FLAGS_DEBUG} ${CERBERUS_SANITIZER_FLAGS}" CACHE STRING
  "Flags used by the CXX compiler during DebugWithSanitizers builds."
  FORCE)
set(CMAKE_C_FLAGS_DEBUGWITHSANITIZERS "${CMAKE_C_FLAGS_DEBUG} ${CERBERUS_SANITIZER_FLAGS}" CACHE STRING
  "Flags used by the C compiler during DebugWithSanitizers builds."
  FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUGWITHSANITIZERS
  "${CMAKE_EXE_LINKER_FLAGS_DEBUG} ${CERBERUS_SANITIZER_FLAGS}" CACHE STRING
  "Flags used for linking binaries during DebugWithSanitizers builds."
  FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_DEBUGWITHSANITIZERS
  "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} ${CERBERUS_SANITIZER_FLAGS}" CACHE STRING
  "Flags used by the shared libraries linker during DebugWithSanitizers builds."
  FORCE)
mark_as_advanced(
  CMAKE_CXX_FLAGS_DEBUGWITHSANITIZERS
  CMAKE_C_FLAGS_DEBUGWITHSANITIZERS
  CMAKE_EXE_LINKER_FLAGS_DEBUGWITHSANITIZERS
  CMAKE_SHARED_LINKER_FLAGS_DEBUGWITHSANITIZERS)


function(SETUP_TARGET_FOR_SANITIZERS)
	set(options NONE)
	set(oneValueArgs NAME)
	set(multiValueArgs EXECUTABLE EXECUTABLE_ARGS DEPENDENCIES)
	cmake_parse_arguments(Sanitizers "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

	if (CMAKE_BUILD_TYPE STREQUAL "DebugWithSanitizers")
		add_custom_target(${Sanitizers_NAME}
			COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=${CERBERUS_ASAN_OPTIONS} UBSAN_OPTIONS=${CERBERUS_UBSAN_OPTIONS} ./${Sanitizers_EXECUTABLE}
		)
	endif()
endfunction() # SETUP_TARGET_FOR_SANITIZERS
