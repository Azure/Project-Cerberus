# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	Coverage.cmake
#
# Abstract:
#
#   Sets up the options for capturing code coverage from unit tests
#
# --

#
# Define cmake options and their defaults
# 
find_program( GCOV_PATH gcov )
find_program( LCOV_PATH lcov )
find_program( GENHTML_PATH genhtml )

set(COVERAGE_COMPILER_FLAGS "-g -O0 --coverage -fprofile-arcs -ftest-coverage"
	CACHE INTERNAL "")

set(CMAKE_CXX_FLAGS_COVERAGE
	${COVERAGE_COMPILER_FLAGS}
	CACHE STRING "Flags used by the C++ compiler during coverage builds."
	FORCE )
set(CMAKE_C_FLAGS_COVERAGE
	${COVERAGE_COMPILER_FLAGS}
	CACHE STRING "Flags used by the C compiler during coverage builds."
	FORCE )
mark_as_advanced(CMAKE_CXX_FLAGS_COVERAGE CMAKE_C_FLAGS_COVERAGE)

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
	link_libraries(gcov)
else()
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COVERAGE_COMPILER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COVERAGE_COMPILER_FLAGS}")

function(SETUP_TARGET_FOR_COVERAGE)

    set(options NONE)
    set(oneValueArgs NAME)
    set(multiValueArgs EXECUTABLE EXECUTABLE_ARGS DEPENDENCIES)
    cmake_parse_arguments(Coverage "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_custom_target(${Coverage_NAME}
        # Cleanup lcov
        COMMAND ${LCOV_PATH} --directory . --zerocounters

        # Run tests
        COMMENT "Running unit tests and generating coverage report"
        COMMAND ${Coverage_EXECUTABLE}

        COMMAND ${LCOV_PATH} -c -d ${PROJECT_BINARY_DIR}/CMakeFiles -o coverage.info -q
        COMMAND ${LCOV_PATH} --remove coverage.info "*/testing/*" "*/mbedtls*" -o coverage.info -q
        COMMAND ${GENHTML_PATH} coverage.info --output-directory ${PROJECT_BINARY_DIR}/coverage_report -q
    )

    add_custom_command(TARGET ${Coverage_NAME} POST_BUILD
        COMMAND ;
        COMMENT "Coverage report can be found in coverage_report"
    )

endfunction() # SETUP_TARGET_FOR_COVERAGE
