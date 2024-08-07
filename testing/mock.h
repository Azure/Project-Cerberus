// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MOCK_H_
#define MOCK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


struct mock_arg;


/**
 * Signature for a custom validation routine to execute more complicated argument validation.
 *
 * No error output for argument validation will be generated by standard mock validation flows when
 * using custom validation.  It is required that validation error messages be generated during
 * execution of the custom routine.
 *
 * Neither argument passed for validation will be null.
 *
 * @param arg_info Information about the argument being validated for use in validation error
 * messages.
 * @param expected Pointer to the expected data for the argument.
 * @param actual Pointer to the actual data passed to the function.
 *
 * @return 0 if the argument contained the expected data or 1 if not.
 */
typedef int (*mock_arg_validator) (const char *arg_info, void *expected, void *actual);

/**
 * Allocate memory and save the data for a pointer argument on a function call.
 *
 * @param expected The expectation context for the argument to save.
 * @param call The calling context for the argument to save.
 */
typedef void (*mock_arg_alloc) (const struct mock_arg *expected, struct mock_arg *call);

/**
 * Allocate memory and save data to be used for argument expectations.
 *
 * @param arg_data The data to copy into the expectation argument.
 * @param arg_length The length of the data to copy.
 * @param arg_save The argument buffer to copy the data to.
 *
 * @return 0 if the data was successfully copied or an error code.
 */
typedef int (*mock_arg_alloc_expect) (const void *arg_data, size_t arg_length, void **arg_save);

/**
 * Release memory for saved pointer argument data.
 *
 * @param arg The argument data to free.
 */
typedef void (*mock_arg_free) (void *arg);

/**
 * Copy output data from an expectation to a function argument.
 *
 * @param expected The expectation context for the argument to copy.
 * @param call The calling context to copy into.
 * @param out_len Buffer space available in the function argument.
 */
typedef void (*mock_arg_copy) (const struct mock_arg *expected, struct mock_arg *call,
	size_t out_len);

/**
 * A container for a function argument description.
 */
struct mock_arg {
	int64_t value;					/**< The expected value of the argument. */
	void *ptr_value;				/**< Data stored in the pointer argument. */
	size_t ptr_value_len;			/**< The length of the data stored at the pointer value. */
	mock_arg_validator validate;	/**< Custom validation routine for the argument. */
	const void *out_data;			/**< Treat the parameter as an output and return this data. */
	size_t out_len;					/**< The maximum length of the output data. */
	int size_arg;					/**< The argument that defines the provided buffer size. */
	int save_arg;					/**< The ID to use for saving the value of the called argument. */
	uint32_t flags;					/**< Validation flags for the argument. */
	mock_arg_alloc alloc;			/**< Allocation function for saving pointer argument data. */
	mock_arg_free free;				/**< Function to free saved pointer argument data. */
	mock_arg_copy copy;				/**< Function to copy data into an output paramater. */
	mock_arg_free out_free;			/**< Function to free the local copy of output data. */
};


/**
 * Flags to set on a mock argument.
 */
enum {
	MOCK_ARG_FLAG_ANY_VALUE = 0x01,			/**< The argument value does not matter. */
	MOCK_ARG_FLAG_NOT_NULL = 0x02,			/**< The argument can be anything as long as it is not NULL (0). */
	MOCK_ARG_FLAG_SAVED_VALUE = 0x04,		/**< The argument should be validated against a saved value. */
	MOCK_ARG_FLAG_ALLOCATED = 0x08,			/**< The argument pointer is managed by the mock. */
	MOCK_ARG_FLAG_OUT_ALLOCATED = 0x10,		/**< The argument output data is managed by the mock. */
	MOCK_ARG_FLAG_PTR_PTR = 0x20,			/**< The argument is a pointer to a pointer that should be dereferenced. */
	MOCK_ARG_FLAG_PTR_PTR_NOT_NULL = 0x40,	/**< The pointer referenced by the pointer argument can be anything except NULL (0). */
	MOCK_ARG_FLAG_OUT_PTR_PTR = 0x80,		/**< The argument output data should be stored at a pointer referenced by another pointer. */
	MOCK_ARG_FLAG_GREATER_EQUAL = 0x100,	/**< Check that an argument is at least a specific value. */
	MOCK_ARG_FLAG_GREATER = 0x200,			/**< Check that an argument is larger than a specific value. */
	MOCK_ARG_FLAG_LESS_EQUAL = 0x400,		/**< Check that an argument is no more than a specific value. */
	MOCK_ARG_FLAG_LESS = 0x800,				/**< Check that an argument is less than a specific value. */
};

struct mock_call;


/**
 * Defines a callback that can be provided for an expectation to execute custom workflows in
 * response to a call at run time.
 *
 * This action will be called before processing any of the called arguments.  This means the called
 * argument list contains the raw argument values passed to the function and have not been updated
 * with any output data.
 *
 * Do not change any contents of either the expected or called structures.  The contents can be
 * checked as part of the custom workflows, but they must not be modified.
 *
 * @param expected The expectation that is being used to validate the current call on the mock.
 * @param called The context for the actual call on the mock.
 *
 * @return This function can return anything that it determines to be appropriate.  A return of 0
 * causes mock processing for the call to proceed normally.  If it returns non-zero, the return
 * value of this function will be used as the return value from the mock, overriding the return
 * value specified when the expectation was created.
 */
typedef int64_t (*mock_call_action) (const struct mock_call *expected,
	const struct mock_call *called);

/**
 * An expectation for a call to the mock.
 */
struct mock_call {
	struct mock_call *next;		/**< The next function call in the list. */
	const void *func;			/**< The expected function. */
	const void *instance;		/**< The firmware image instance calling the function. */
	int argc;					/**< The number of arguments. */
	struct mock_arg *argv;		/**< The arguments to the function. */
	int64_t return_val;			/**< The value to return for the call. */
	mock_call_action action;	/**< A custom action to execute while processing the call. */
	void *context;				/**< User context provided for the custom action. */
};

/**
 * A container for argument values saved for use by expectations.
 */
struct mock_save_arg {
	struct mock_save_arg *next;		/**< The next saved argument in the list. */
	int id;							/**< The ID of the saved argument. */
	bool saved;						/**< Flag indicating if a value was saved in this container. */
	int64_t value;					/**< The saved argument value. */
	struct mock_save_arg *shared;	/**< A link a shared instance for this saved argument. */
};

/**
 * The base information for a mock instance.
 */
struct mock {
	const char *name;				/**< The name of the mock instance. */
	struct mock_call *expected;		/**< The list of expected function calls. */
	struct mock_call *exp_tail;		/**< The end of the expected list. */
	int exp_count;					/**< The number of expected calls. */
	struct mock_call *called;		/**< The list of functions that were called. */
	struct mock_call *call_tail;	/**< The end of the called functions list. */
	int call_count;					/**< The number of called functions. */
	struct mock_call *next_call;	/**< The expected function that will be called next. */
	struct mock_save_arg *save;		/**< The list of saved argument values. */
	int next_id;					/**< The next available saved argument ID. */

	/**
	 * Get the number of arguments for a mocked function.
	 *
	 * @param func The mocked function.
	 *
	 * @return The number of arguments for the function.
	 */
	int (*func_arg_count) (void *func);

	/**
	 * Function to map a function pointer to a function name.
	 *
	 * @param func The function to map.
	 *
	 * @return The name of the function.
	 */
	const char* (*func_name_map) (void *func);

	/**
	 * Function to  map a function argument to a name.
	 *
	 * @param func The function for the argument to map.
	 * @param arg The argument index.
	 *
	 * @return The name of the function argument.
	 */
	const char* (*arg_name_map) (void *func, int arg);
};

/**
 * Structure to pass to the mock when setting expectations on a function.
 */
struct mock_expect_arg {
	int64_t value;					/**< The expected value of the argument. */
	size_t ptr_value_len;			/**< The length of data that should be validated at a pointer location. */
	mock_arg_validator validate;	/**< Custom validation routine for the argument. */
	int save_arg;					/**< The ID of the saved argument entry to use for validation. */
	uint32_t flags;					/**< Validation flags for the argument. */
	mock_arg_alloc alloc;			/**< Allocation function for saving pointer argument data. */
	mock_arg_free free;				/**< Function to free saved pointer argument data. */
	mock_arg_alloc_expect copy;		/**< Function to make a copy of the argument data. */
};


/**
 * Expectation that an argument will be a specific value.  This should only be used with integer
 * values.  If the argument is a pointer, use MOCK_ARG_PTR instead.
 */
#define MOCK_ARG(x)	((struct mock_expect_arg) { \
	.value = (int64_t) x, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = 0, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument can be any value.
 */
#define MOCK_ARG_ANY	((struct mock_expect_arg) { \
	.value = 0, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_ANY_VALUE, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument will be at least a specific value.  This will be treated as a signed
 * integer value.
 */
#define MOCK_ARG_AT_LEAST(x)	((struct mock_expect_arg) { \
	.value = (int64_t) x, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_GREATER_EQUAL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument will be larger than a specific value.  This will be treated as a
 * signed integer value.
 */
#define MOCK_ARG_MORE_THAN(x)	((struct mock_expect_arg) { \
	.value = (int64_t) x, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_GREATER, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument will be no larger than a specific value.  This will be treated as a
 * signed integer value.
 */
#define MOCK_ARG_NO_MORE_THAN(x)	((struct mock_expect_arg) { \
	.value = (int64_t) x, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_LESS_EQUAL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument will be less than a specific value.  This will be treated as a
 * signed integer value.
 */
#define MOCK_ARG_LESS_THAN(x)	((struct mock_expect_arg) { \
	.value = (int64_t) x, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_LESS, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument can be any value expect null or 0.
 */
#define MOCK_ARG_NOT_NULL	((struct mock_expect_arg) { \
	.value = 0, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument will be a specific pointer.
 */
#define MOCK_ARG_PTR(ptr)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = 0, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to a location that contains the expected data.
 */
#define MOCK_ARG_PTR_CONTAINS(ptr, len)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to a location that contains the expected data.  The
 * expected data is stored in a temporary variable that will not be in scope during validation, so
 * the data is copied into the expectation context.
 */
#define MOCK_ARG_PTR_CONTAINS_TMP(ptr, len)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL | MOCK_ARG_FLAG_ALLOCATED, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument value matches that of a saved argument value.
 */
#define MOCK_ARG_SAVED_ARG(id)	((struct mock_expect_arg) { \
	.value = 0, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = id, \
	.flags = MOCK_ARG_FLAG_SAVED_VALUE, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to data that will be validated with a custom validation
 * routine.  The validation routine must comply with {@link mock_arg_validator}.
 */
#define	MOCK_ARG_VALIDATOR(func, ptr, len)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = func, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to data that will be validated with a custom validation
 * routine.  The validation routine must comply with {@link mock_arg_validator}.  The expected data
 * is stored in a temporary variable that will not be in scope during validation, so the data is
 * copied into the expectation context.
 */
#define	MOCK_ARG_VALIDATOR_TMP(func, ptr, len)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = func, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL | MOCK_ARG_FLAG_ALLOCATED, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to data that will be validated with a custom validation
 * routine.  The validation routine must comply with {@link mock_arg_validator}.  The argument data
 * will be copied and released using the provided allocation and free functions.  They can be set to
 * null to use the default functions.
 */
#define	MOCK_ARG_VALIDATOR_DEEP_COPY(func, ptr, len, save, rel)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = func, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL, \
	.alloc = save, \
	.free = rel, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to data that will be validated with a custom validation
 * routine.  The validation routine must comply with {@link mock_arg_validator}.  The expected data
 * is stored in a temporary variable that will not be in scope during validation, so the data is
 * copied into the expectation context.  The argument data will be copied and released using the
 * provided allocation and free functions.  They can be set to null to use the default functions.
 */
#define	MOCK_ARG_VALIDATOR_DEEP_COPY_TMP(func, ptr, len, save, rel, dup)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = func, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL | MOCK_ARG_FLAG_ALLOCATED, \
	.alloc = save, \
	.free = rel, \
	.copy = dup})

/**
 * Expectation that an argument is a pointer to a pointer to a specific location.
 */
#define MOCK_ARG_PTR_PTR(ptr)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL | MOCK_ARG_FLAG_PTR_PTR, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to a pointer to any location except null or 0.
 */
#define MOCK_ARG_PTR_PTR_NOT_NULL	((struct mock_expect_arg) { \
	.value = 0, \
	.ptr_value_len = 0, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL | MOCK_ARG_FLAG_PTR_PTR | MOCK_ARG_FLAG_PTR_PTR_NOT_NULL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to a pointer to a location that contains the expected
 * data.
 */
#define MOCK_ARG_PTR_PTR_CONTAINS(ptr, len)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL | MOCK_ARG_FLAG_PTR_PTR | MOCK_ARG_FLAG_PTR_PTR_NOT_NULL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})

/**
 * Expectation that an argument is a pointer to a pointer to a location that contains the expected
 * data.  The expected data is stored in a temporary variable that will not be in scope during
 * validation, so the data is copied into the expectation context.
 */
#define MOCK_ARG_PTR_PTR_CONTAINS_TMP(ptr, len)	((struct mock_expect_arg) { \
	.value = (int64_t) ((uintptr_t) ptr), \
	.ptr_value_len = len, \
	.validate = NULL, \
	.save_arg = -1, \
	.flags = MOCK_ARG_FLAG_NOT_NULL | MOCK_ARG_FLAG_ALLOCATED | MOCK_ARG_FLAG_PTR_PTR | MOCK_ARG_FLAG_PTR_PTR_NOT_NULL, \
	.alloc = NULL, \
	.free = NULL, \
	.copy = NULL})


/**
 * The return value from an expectation is a pointer.
 */
#define	MOCK_RETURN_PTR(ptr)	(int64_t) ((uintptr_t) ptr)


int mock_expect (struct mock *mock, void *func_call, void *instance, int64_t return_val, ...);

int mock_expect_output (struct mock *mock, int arg, const void *out_data, size_t out_length,
	int length_arg);
int mock_expect_output_tmp (struct mock *mock, int arg, const void *out_data, size_t out_length,
	int length_arg);
int mock_expect_output_ptr (struct mock *mock, int arg, const void *out_data, size_t out_length,
	int length_arg);
int mock_expect_output_ptr_tmp (struct mock *mock, int arg, const void *out_data, size_t out_length,
	int length_arg);
int mock_expect_output_deep_copy (struct mock *mock, int arg, const void *out_data,
	size_t out_length, mock_arg_copy copy);
int mock_expect_output_deep_copy_tmp (struct mock *mock, int arg, const void *out_data,
	size_t out_length, mock_arg_copy copy, mock_arg_alloc_expect out_copy, mock_arg_free free);

int mock_expect_save_arg (struct mock *mock, int arg, int id);
int mock_expect_next_save_id (struct mock *mock);
int mock_expect_share_save_arg (struct mock *from, int src_id, struct mock *to, int dest_id);

int mock_expect_external_action (struct mock *mock, mock_call_action action, void *context);

int mock_validate (struct mock *mock);


#define	MOCK_ERROR(code)		ROT_ERROR (ROT_MODULE_MOCK, code)

/**
 * Error codes that can be generated by a mock object.
 */
enum {
	MOCK_INVALID_ARGUMENT = MOCK_ERROR (0x00),	/**< Input parameter is null or not valid. */
	MOCK_NO_MEMORY = MOCK_ERROR (0x01),			/**< Memory allocation failed. */
	MOCK_NO_EXPECTATION = MOCK_ERROR (0x02),	/**< No expectation to modify. */
	MOCK_BAD_ARG_INDEX = MOCK_ERROR (0x03),		/**< Argument index is not valid for the call. */
	MOCK_SAVE_ARG_EXISTS = MOCK_ERROR (0x04),	/**< A saved argument already exists for an ID. */
	MOCK_NO_SAVE_ARG = MOCK_ERROR (0x05),		/**< No saved argument for an ID. */
	MOCK_BAD_ARG_LENGTH = MOCK_ERROR (0x06),	/**< Argument data is not a valid length. */
};


/* Calls for derived mock internal use. */

int mock_init (struct mock *mock);
void mock_release (struct mock *mock);

void mock_set_name (struct mock *mock, const char *name);

struct mock_call* mock_allocate_call (const void *func, const void *instance, size_t args, ...);


int64_t mock_return_from_call (struct mock *mock, struct mock_call *call);


#define MOCK_ARG_CALL(x)		((int64_t) x)
#define	MOCK_ARG_PTR_CALL(ptr)	((int64_t) ((uintptr_t) ptr))
#define MOCK_ARG_COUNT(...)		(sizeof ((int64_t[]) {__VA_ARGS__}) / sizeof (int64_t))

#define MOCK_VOID_RETURN(mock, func, inst, ...) \
	mock_return_from_call (mock, \
		mock_allocate_call (func, inst, MOCK_ARG_COUNT (__VA_ARGS__), __VA_ARGS__))

#define MOCK_VOID_RETURN_NO_ARGS(mock, func, inst) \
	mock_return_from_call (mock, mock_allocate_call (func, inst, 0))

#define MOCK_RETURN(mock, func, inst, ...)	return MOCK_VOID_RETURN (mock, func, inst, __VA_ARGS__)
#define MOCK_RETURN_NO_ARGS(mock, func, inst)	return MOCK_VOID_RETURN_NO_ARGS (mock, func, inst)

#define MOCK_RETURN_CAST(mock, cast, func, inst, ...)   \
	return (cast) (MOCK_VOID_RETURN (mock, func, inst, __VA_ARGS__))
#define MOCK_RETURN_NO_ARGS_CAST(mock, cast, func, inst) \
	return (cast) (MOCK_VOID_RETURN_NO_ARGS (mock, func, inst))

#define MOCK_RETURN_CAST_PTR(mock, cast, func, inst, ...)   \
	return (cast) ((uintptr_t) (MOCK_VOID_RETURN (mock, func, inst, __VA_ARGS__)))
#define MOCK_RETURN_NO_ARGS_CAST_PTR(mock, cast, func, inst) \
	return (cast) ((uintptr_t) (MOCK_VOID_RETURN_NO_ARGS (mock, func, inst)))


#endif	/* MOCK_H_ */
