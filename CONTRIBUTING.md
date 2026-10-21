The Project Cerberus code follows a set of development guidelines and coding conventions to ensure
quality components that have the same general construction, making it easier to navigate the code
base.  While it's possible to find code that contradicts some of these guidelines, these should be
treated as an exception and not duplicated.  Several of these guidelines grew over time, and may not
have been fully applied to older code yet.

# C Language Code Style

There is an uncrustify configuration file provided that can apply most of the formatting
requirements to code.  It has been tested to work with version 0.78.1_f with decent results.  Using
older versions (such as 0.69) do not produce as well formatted code.

Running an appropriate version of uncrustify (currently 0.78.1_f) with the provided configuration on
any submitted files is a requirement for any C code contributions.  Note that even with uncrustify,
there may still be a need for some manual formatting.  For example, array initializer wrapping does
not always produce easily readable data, and may need manual formatting (See [Arrays](#Arrays))

## Indentation

Indentation and alignment use tabs with a tab width of 4.  Do not replace tabs with spaces.  Each
level of control receives one additional indent.

### Switch

Within a `switch` statement, each `case` will be indented one additional level.  Statements within
the `case` will be additionally indented relative to the `case`, which includes the `break` statement.
There should be a newline between each `case`.

```
switch (value) {
	case 0:
		Do something;
		break;

	case 1:
		Do something else;
		break;

	default:
		Default behavior;
		break;
}
```

## Breaking Long Lines

The column limit is 100 characters.  Anything longer will need to be wrapped.
- Function declarations and invocations will get wrapped at the column limit following a parameter.
If the column limit is reached at the first parameter, the line should wrap after the opening
parenthesis, even if this itself exceeds the column limit.
- Conditionals will get wrapped after a binary operator (&&, ||, etc.).  It should be preferred to
wrap a complete clause of a multi-clause conditional.
- Assignment will get wrapped after the operator.  If entire expression being assigned can be
wrapped to the next line, that should generally be preferred rather than wrapping in the middle of
the expression.
- Ternary operators should prefer wrapping that keeps both execution options on one line, if that
is achievable within the column limit.

When wrapping a line, the next line gets an additional level of indent, indicating a continuation of
the context on the previous line.  For particularly long lines that need to wrap multiple times,
subsequent lines will maintain the indentation of the previous line.  The exception is when a new
context gets opened that itself needs to be wrapped (e.g. calling a function from within a
conditional or function call).  In this case, the next context should get an additional indent.
If there are additional components to the original context, the line should be wrapped and returned
to the previous ident level.

Exceptions when line wrapping is not always necessary:
1. Trailing comments on struct fields or enum values.  However, even in this case, line length
should be limited.  If the trailing comments exceed 150 columns, it's often preferable to move the
comment before the item rather than use a trailing comment.
2. \#defines can exceed the column limit when necessary to align with syntax requirements.  In most
cases, \#defines that exceed the column limit should be defined across multiple lines.
3. Adding test cases to a test suite.  Test names can get quite long and wrapping them between
TEST_SUITE_START/TEST_SUITE_END calls serves no readability benefit.  `*INDENT-OFF*` should be used
when defining test suites with long names to avoid this wrapping when using uncrustify.

Examples:

```
call_a_short_function (arg);

call_a_long_function_with_many_args (arg1, arg2, arg3,
	arg4, arg5, arg6);

int define_a_function_with_a_long name (
	arg1, arg2, arg3);

if ((arg1 == 0) ||
	(arg2 == 1)) {
	Do something;
}

if ((long_conditional_clause <= some_local_value) &&
	bool_check)

val = (1 << 4) | (1 << 6) |
	(1 << 8);

val =
	5 + some_long_function_call (arg1, arg2);

val = (long_conditional_check) ?
	5 : 7;

mock_expect (&mock.mock, mock.base.func, &mock, 0,
	MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (long_variable_name,
		long_variable_size),
	MOCK_ARG (long_variable_size));

mock_expect (&mock.mock, mock.base.func, &mock, 0,
	MOCK_ARG (1),
	MOCK_ARG_PTR_CONTAINS (long_variable_name,
		long_variable_size),
	MOCK_ARG (long_variable_size));
```

Note: As of 0.78_1.f, uncrustify does not handle wrapping these embedded contexts, giving
everything a single indent.  If future versions of uncrustify provide this capability, it can be
enabled to generate this formatting at that time.

## Comments

### Documentation of Defined Types

Every defined function or type needs a comment block documenting its details.  Comment blocks for
this purpose with the /** Doxygen marker, using the Javadoc style.

[Doxygen commenting details](https://www.doxygen.nl/manual/docblocks.html)

Note that example comments in this section are for illustrative purposes only.  Actual comments in
code should generally be more descriptive, and not just repeat the variable or type name as a
comment.

#### Functions

Every function definition needs a comment block describing what the function does, what the parameters
represent, and what is returned.  The function description needs to be provide sufficient details to
make it clear how it will behave, which includes and preconditions and/or side-effects of the call.
Function comment blocks will be located in the .c file where the function is implemented.

Virtual functions that are defined as part of an interface have the same commenting requirements.
The difference here is that the comment is placed in the .h file where the function is declared.
This is because the comment block in this case is defining the contract that any implementation of
the function must adhere to.  Specific implementations assigned to these function pointers will not
have a comment block, since they inherit the comment from the interface definition.

```
/**
 * A detailed function description.
 *
 * @param arg1 A function argument.
 * @param arg2 Another one.
 * @param arg3 Output parameter for some data.
 *
 * @return 0 on success or an error code.
 */
int foo (int arg1, int arg2, int *arg3)
{

}
```

#### Structs

Every struct must have a comment block describing what it represents.  Most of the time, a struct is
used to represent the instance type for a software module, which means this comment block doubles as
a description of the module itself.  Much like function comments, this documentation should be
sufficiently detailed to make it clear what role the module fulfills.

Within a struct, every field must be commented, detailing it's purpose.  Function pointers are
documented as described previously.  Other fields will be documented with either a trailing comment
block using the /**< Doxygen tag or with a standard comment block before the field.

Trailing comment blocks on fields should be tab-aligned with each other in the same struct.

```
/**
 * A module that does something interesting.
 */
struct some_module {
	/**
	 * Expose some functionality as a public API.
	 *
	 * @param arg A function argument.
	 *
	 * @returns 0 if the function was successful or an error code.
	int (*foo) (int arg);

	uint8_t val;				/**< Private field. */
	uint32_t long_name_val;		/**< Private field with a long name */

	/**
	 * Private field with a long description
	 * that needs wrapping.  Using a standard
	 * comment block improves readability of
	 * the description.
	 */
	uint16_t long_desc_val;
};
```

#### Enums

Enum definitions have the same commenting requirements as structs.

#### Global and Static Variables

Global and static variables need documentation describing what the variable represents.  This is
true for both const and non-const variables.  These declarations will use the standard Doxygen
comment block rather than a trailing comment.

The exception to this rule are `_LEN` variables (or macros) in test code.  They are always the
length of the array preceding it, which would be documented.

```
/**
 * Global constant variable.
 */
const int CONST_VAR = 100;

/**
 * Instance of the foo type.
 */
static struct foo instance;
```

#### Macros

Macros follow the same documentation requirements as global and static variables.  If the macro
takes arguments, it should follow the same documentation structure as a function.

```
/**
 * Defined constant.
 */
#define CONST_VAL		200

/**
 * Macro that takes arguments.
 *
 * @param x First argument.
 * @param y Second argument.
 *
 * @return A modified value.
 */
#define macro_function(x, y)	(((x) << 4) | ((y) & 0x0f))
```

### Comments in Code

Code should be commented in-line when appropriate for clarifying pieces that may not be obvious.
This includes clarifying why certain code exists based on experimental or external information.
Comments should be limited to pieces that add value and clarity.

Single line comments, whether they are on their own or are a trailing comment following some code
segment can use either `/* */` or `//` style comments.  Multi-line comments use `/* */` with a `*`
at the beginning of each line.

```
/* This is a single line comment. */

// Another single line comment.

val = 7;	/* Trailing comment */

/* This is a
 * multi-line
 * comment. */
```

## Braces

Conditionals, loops, and switch statements will have the opening brace on the same line with the
closing brace on a newline.  Every conditional must have braces, regardless of how many lines are
controlled by the conditional.

```
if (condition) {
	Do something;
}

while (condition) {
	Loop;
}

switch (value) {
	default:
		break;
}
```

If a `case` defines local variables within a new scope, bracing follows the same construction as the
switch.

```
switch (value) {
	default: {
		int var;

		Do something;
		break;
	}
}
```

`do .. while` loops have slightly different handling for the brace.

```
do {

} while (condition);
```

When a conditional includes an `else` statement, the else will be on a newline.

```
if (condition) {
	Do something;
}
else {
	Do something else;
}
```

Structs, enums, and unions follow the same rules for braces.

```
struct {
	int val;
};

enum {
	ENUM_VALUE,
};

union {
	int val1;
	char val2;
};
```

Functions are the exception where both open and closing braces are their own lines.

```
int foo (int arg)
{
	Do something;
}
```

## Parenthesis

Parenthesis should be used for visual grouping of components in conditionals with multiple clauses
or complex expressions.  Grouping and ordering should be obvious based on parenthesis without needing
to decern order of operations.

In conditionals, single boolean checks do not need parenthesis.

For ternary operations, the initial condition should be enclosed in parenthesis as if it was an `if`
statement.

```
if ((arg == 1) && (val == 2)) {

}

if (check || !force || (arg == 3)) {

}

val = (is_true) ? 1 : 0

val = ((1 * 4) + (3 * 4));

val = 1 + 4;
```

## Spaces

A space should be added before the opening parenthesis following keywords, functions, macros, etc.
A space should be added after the closing parenthesis in these case, as well as for casting.
A space should not be added inside the parenthesis for conditionals or other compound statements.

The exception to this rule is when defining macros with parameters, since the syntax requires there
to be no space in this case.

```
func (arg);

while (condition);

sizeof (struct foo);

if ((arg1 == 1) && (arg2 == 2)) {
	Do something;
}

a = (int) b;
```

There should be a space around binary operators such as

```
=  +  -  <  >  *  /  %  |  &  ^  <=  >=  ==  !=  ?  :
```

```
i = 5 + 3;

j = (check != expected) ? value : other;
```

There should be no space after unary operators such as

```
&  *  -  ~  !  ++  --
```

Also no space around `.` or `->` accessors for struct fields.

```
int *i = &x;

foo.x = 5;

i++;
--i;

if (!is_true) {

}
```

Remove trailing whitespace at the end of lines and on blank lines.  Also ensure each source file
ends with a newline.

## Pointers

The `*` for pointers should be next to the variable and not the data type.

```
int *ptr;

int func (int *arg);

void (*func_ptr) (int arg);
```

When a function returns a pointer or there is a pointer cast, the `*` will be next to the type.

```
char* get_str ();

uint8_t *x = (uint8_t*) &y;
```

## Typedefs

For most scenarios, typedefs are not used.  They only exist in a couple of places:
1. Declaring function pointer types used in callback scenarios.  This is rare as most handling of
this type uses structures with function pointers.
2. Some enum definitions in older code that never got updated.  This case shouldn't be repeated.

In all scenarios, explicit types should be passed as arguments to make it clear what is being used.

```
int func (struct foo *arg, enum arg_type type);
```

This is based on the rationale presented in the Linux kernel coding style, which served as a
reference for several stylistic decisions.

## Declaring Variables

Variables should only be defined at the beginning of a scope and should be separated from code with
a newline.  Variables used by `for` loops should not be defined in-line as part of the beginning of
the loop.

There should be only one variable declaration per line.

```
int func () {
	int a;
	int b;

	for (a = 0; a < 4; a++) {
		char c = 'c';

		Do stuff;
	}
}
```

## Initializing Arrays and Structs

Whenever initializing to 0, the initialization should take place on a single line.

```
int arr[5] = {0};

struct foo var = {0};
```

### <a name="Arrays"></a>Arrays

Array initialization should be done to maintain the best readability of the array data.  There
should be a space after the comma between each array element.  Most byte arrays should be wrapped
after 16 bytes of data and use two hex characters per byte, which maintains a similar view as a
typical hex dump.  For arrays that have more than a single indent, wrapping after 8 bytes should be
preferred, since 16 bytes exceeds the column limit.

There are other scenarios that may have different needs to better provide visual understanding of
the data.
- For test vectors that represent formatted command data, grouping the data the same as or similar
to the command structure makes it easy to see the different command components.
- Arrays that are not bytes might have different logical groupings.  For example, SFDP arrays are
of DWORDS that map to the spec.  Having each on its own line allows for easy visual mapping of
values.

```
uint8_t arr[] = {
	0x00, 0x01, 0x02 ... 0x0f,
	0x10, 0x11, 0x12 ... 0x1f,
	0x20, 0x21
};
```

### Structs

Structure initialization should be done to make it clear and obvious what is being initialized.
This means assigning each field by name, with each field on a new line.

```
struct foo var = {
	.arg1 = 1,
	.arg2 = 2,
	.arg3 = 3
};
```

## Naming

Functions, types, variables, etc. are defined using snake case.  Macros and variables that represent
constants are capitalized snake case.

```
int function_name (char some_arg)
{
	int local_var;
}

#define CONST_MACRO		200

const int CONST_VAR = 100;
```

### File and Module Naming

Each module will exist in a set of files (.c/.h) that share the module name.  If the module defines
an object, the struct will be named to match the file name.  Everything associated with a particular
module should be prefixed with name of the module.  This includes public or static functions and
types, public or private macros, and static variables.

```
some_type.c
some_type.h
some_type_static.h

struct some_type {
	int val;
};

int some_type_func (int arg);

#define SOME_TYPE_MACRO		3
```

The test suite associated with a particular module will exist in a file that matches the module
name, but is appended with _test.  If a test suite exposes functions, variables, or types for use in
other tests, these will be declared in a header file appended with _testing.  Within a test suite,
helper functions, test vectors, test types, etc. will be named with the module name, appending with
_testing.  Each test case will have _test appended instead, followed by the function and scenario
being tested:  `<module>_test_<func>_<scenario>`.

```
some_type_test.c
some_type_testing.h

const uint8_t SOME_TYPE_TESTING_EXPECTED = 3;

struct some_type_testing {
	struct some_type test;
};

static void some_type_testing_init_dependencies (CuTest *test, struct some_type_testing *arg)
{

}

static void some_type_test_init (CuTest *test)
{

}

static void some_type_test_func_unexpected_arg (CuTest *test)
{

}
```

If the module being developed does not have a type associated with it and is just a set of utility
functions, it will sometimes have the name `*_util`.  In this case, macros, functions, tests, etc.
(except for module error codes) drop the `util` from the name.  For example, see
`asn1/ecc_der_util.h`.

### Abstract and Derived Types

When defining an abstract type (a type that exposes an API of function pointers), the base type can
be named as `interface` (e.g. `some_type_interface`).  File and type naming rules remain the same in
this case.

When deriving an abstract type, the base type name is used, followed by the derivation name.  If the
base type used the `interface` naming, this is dropped from the derived name.  The first field of
the derived type would be the base type and the field name should be `base`.

```
struct some_type_interface {
	int (*func_ptr) (const struct some_type_interface *obj, int arg);
};

struct some_type_derived {
	struct some_type_interface base;
};

struct some_type_derived_again {
	struct some_type_derived base;
};

struct some_other_type {
	int (*func_ptr) (const struct some_other_type *obj, int arg);
};

struct some_other_type_derived {
	struct some_other_type base;
};
```

In the case of multiple inheritance, all derived types should be first in the structure definition
and would have some `base` naming to differentiate which base it is.  If there is a primary base
type, that may opt to be named `base` with other base types having a qualifier on `base`.

Since these types are not directly related with a single base type, naming has more flexibility.
1. It can be named based on the primary base type.
2. It can be name independent of any base type.

```
struct multi_type {
	struct some_type_interface base_some;
	struct some_other_type base_other;
};

struct some_type_multi {
	struct some_type_interface base;
	struct some_other_type base_other;
};
```

### Virtual Functions

Virtual functions defined as part of an abstract type don't follow the same naming pattern as other
functions.  They do not get prefixed with the module name, since that binding is already achieved by
being a member of the structure type.

Implementations of virtual functions follow the standard naming approach and will be named with the
derived type name followed by the virtual function being implemented.

```
struct some_type_interface {
	int (*func_ptr) (const struct some_type_interface *obj, int arg);
};

struct some_type_derived {
	struct some_type_interface base;
};

int some_type_derived_func_ptr (const struct some_type_interface *obj, int arg)
{

}
```

## Organization

### Structs

While written in C, the code leverages an object oriented approach with the architecture.  Most
modules have a struct that is used to define the "class" type.  Since C doesn't offer any protection
for different fields in the struct, access permissions come more from policy and usage.  In general,
all fields in structs, which are acting as classes, are considered private (more accurately,
protected).  The exceptions are any virtual functions and base types that are expected to be used
externally.

The order and naming of fields typically convey their permissions.
- Any base type named `base` or `base_*` is public.
- Virtual functions that come first in the struct definition are public.
- Virtual functions that follow one or more base types, but precede any other fields are public.
- The first field that is not one of the above is private (protected).  All fields following this
one are also private.
- Internal virtual functions will generally be last in the definition.

```
struct foo {
	struct base_type base;
	struct another_base_type base_another;

	int (*public_func1) (int arg);

	int (*public_func2) (int arg);

	int private_field1;
	int private_field2;

	int (*private_func) (int arg);
};
```

### Function Arguments

Function arguments are ordered based on how it's consumed by the function in the following order:
- The instance pointer
- Input-only arguments
- Output arguments, including arguments that are also an input (which are rare)

```
int foo (struct some_type *instance, int input_arg1, int input_arg2, int *output_arg1, int *output_arg2);
```

The exception to this ordering are buffer length arguments, which are typically input parameters,
but should immediately follow the buffer the length represents.

```
int foo_with_buffer (struct some_type *instance, int input_arg, uint8_t *output_buffer, size_t length);
```

### Includes

In most cases, include files should be listed as a single group without blank lines in between.
Within each group, includes should be alphabetized.  Includes with fewer sub-directories would come
before ones with a deeper path.  Standard library includes come first.  Testing headers are grouped
together after the other headers.

Successful compilation should not depend on specific ordering of header files.  Any implementation
that would result is such a dependency needs to be adjusted to remove this dependency.

Standard library includes are encapsulated with `<>` and come first in the list.  Project includes
are encapsulated with `""`.

```
#include <stddef.h>
#include <stdint.h>
#include "foo.h"
#include "dir1/bar.h"
#include "dir1/dir2/bar2.h"
#include "zzz/z.h"
#include "testing/mock/dir1/bar_mock.h"
```

### Header Files

Header files are generally organized in the following structure:

```
<Copyright and license header>

#ifndef OBJECT_TYPE_H_
#define OBJECT_TYPE_H_

<Includes>


<Public macros, enums, and supporting types>


struct object_type_state {

};

struct object_type {

};


int object_type_init (struct object_type *object, struct object_type *state);
int object_type_init_state (const struct object_type *object);
void object_type_release (const struct object_type *object);

<Other non-virtual public APIs>

/* Internal functions for use by derived types. */
<Non-virtual protected APIs>


<Module error codes>


#endif /* OBJECT_TYPE_H_ */

```

Not all sections will be present in all files.  When the header is exposing internal functions for
re-use by derived types, the comment in the header delineates public vs. protected APIs.

### Static Init Header

Everything needed to initialize an object statically is contained in a separate header from the main
module header.  This is because static initialization often requires internal functions to be made
externally available.  Having this in a separate file further demonstrates that these declarations
should not be generally used.

A static init header is generally organized in the following structure:

```
<Copyright and license header>

#ifndef OBJECT_TYPE_STATIC_H_
#define OBJECT_TYPE_STATIC_H_

#include "object_type.h"


/* Internal functions declared to allow for static initialization. */
<Implementations for virtual functions>


<Macro(s) for initializing the base API>


<Macro(s) for initializing the instance>
```

When defining the `*_static_init` macros, arguments to the macro often need to be changed so they
don't collide with field names in the structure.  The typical pattern is to append `_ptr` or `_arg`
to the argument, depending on whether it's pointer or not, to achieve this.

```
#define	object_type_static_init(state_ptr, type_ptr, value_arg)	{ \
		.state = state_ptr, \
		.type = type_ptr, \
		.value = value_arg, \
	}
```

### Source Files

Source files are generally organized in the following structure:

```
<Copyright and license header>

<Includes>


<Implementations of virtual APIs>

<Non-virtual public/private APIs, including init/release>
```

The order of function definitions in the source file should generally match the order of
declarations in the header file.

### Test Suites

Test files are generally organized in the following structure:

```
<Copyright and license header>

<Includes>


TEST_SUITE_LABEL ("some_type");


<Constant test vectors or other supporting types>


struct some_type_testing {
	<Other testing dependencies>
	struct some_type_state state;
	struct some_type test;
};


void some_type_testing_init_dependencies (CuTest *test, struct some_type_testing *arg)
{
	<Init all dependencies, but don't init component under test>
}

void some_type_testing_release_dependencies (CuTest *test, struct some_type_testing *arg)
{
	<Validate and release mocks>

	<Release non-mock dependencies>
}

void some_type_testing_init (CuTest *test, struct some_type_testing *arg)
{
	some_type_testing_init_dependencies (test, arg);

	<Init test instance>
}

void some_type_testing_release (CuTest *test, struct some_type_testing *arg)
{
	<Release test instance>

	some_type_testing_release_dependencies (test, arg);
}

<Other helper functions for test cases, typically to set up complicated mock expectations.>


/*******************
 * Test cases
 *******************/

 <Individual test cases>


// *INDENT-OFF*
TEST_SUITE_START (some_type);

<Add test cases to the test suite.  The order in which these are added to the suite should match the
order in which they are defined above.>

TEST_SUITE_END;
// *INDENT-ON*

```

Test cases should be organized to group tests for each API function together.  Within each group of
tests, they should be grouped into successful/normal cases and error/exception cases.  These two
groups are separated by a 'null' test case (which checks for NULL arguments).  'Normal' cases don't
always have a successful status code.  For example, in some cases a signature or data comparison
failure is treated as 'normal' execution.

Example:

```
TEST (some_type_init);
TEST (some_type_init_null);
TEST (some_type_init_some_error);
TEST (some_type_static_init);
TEST (some_type_static_init_null);
TEST (some_type_static_init_some_error);
TEST (some_type_release_null);
TEST (some_type_func);
TEST (some_type_func_another_scenario);
TEST (some_type_func_static_init);
TEST (some_type_func_null);
TEST (some_type_func_some_error_case);
```

### Code Blocks

Within functions, code should be separated with newlines between logical blocks to improve
readability.  What is a meaningful logical block that should be separated is more subjective, but
the goal should be to not have a lot of code packed tightly together.

Following a function call and error check is generally considered a logical break.

```
status = func (arg);
if (status != 0) {
	return status;
}

status = another_call (arg);
if (status != 0) {
	return status;
}
```

# Module Requirements

When creating a new module within the code base, such as a derivation of an interface or a set of
common utility functions, there are a set of standard components that need to be generated.

## Files

Each module should be contained in its own set of files.  Sometimes there are multiple related types
in a single set of files, but this represents a special case.  In all cases, there needs to be the
implementation and test files.

```
some_type.c
some_type.h
testing/some_type_test.c
```

If the module being defined contains an object definition, it will additionally need a file for
statically initializing the instance.  Supporting static initialization is a requirement for all
modules.

```
some_type_static.h
```

If the module object defines a set of virtual functions, it will need a mock implementation.

```
testing/mock/some_type_mock.c
testing/mock/some_type_mock.h
```

## Types

If a new object is being defined, the header file for the module will contain a definition for the
struct representing that object.

```
struct some_type {

};
```

If the object contains only constant references to other dependencies or configuration values, there
may not need to be any other types associated with this module.  However, if there is some amount of
state information that will vary at run-time, the type needs an additional `state` structure to hold
this variable data.  This is necessary to separate the constant and variable state of the object,
allowing it to support constant instances.

```
struct some_type_state {

};

struct some_type {
	struct some_type_state *state;
};
```

## Functions

Every module that implements an object type must provide `init`, `static_init`, and `release`
functions.  If the module contains a `state` structure for variable context, it will also provide an
`init_state` function.

The `init` function provides dynamic initialization that would get executed at run-time
and must fully initialize the object instance.  This includes initializing both constant and
variable information in the instance.  While there are some scenarios in the final application where
this type of initialization could be useful, it's most useful for unit tests.

The `static_init` function is actually a macro defined in the `_static.h` header file.  This macro
will provide full initialization of the constant information for the type.  No variable information
within the `state` structure is handled by this call.  This type of initialization is good for
firmware images, since it allows function pointers and other references to be fixed at compile time.

The `init_state` function pairs with `static_init` to provide run-time initialization of the
variable information present in the instance.  Only contents of the `state` structure may be
modified, as this will most often get called using a constant instance.  In many cases, this
function also checks the instance for NULL or otherwise invalid arguments, ensuring that it was
configured correctly.

The `release` function frees any dynamic resources used by the instance (e.g. mutex).  Only contents
of the `state` structure may be released or modified by this call, since it must support being
called using a constant instance.  In many cases, the `release` call is empty and just serves as a
placeholder.

All functions defined to support an object type must take the object instance as the first argument.
In all cases other than `init`, the object instance must be a `const` pointer argument.  In the case
of `init`, the `state` structure is generally the second argument, since it's considered part of the
instance that is being initialized.

```
some_type.h

int some_type_init (struct some_type *obj, struct some_type_state *state,
	const struct other_type *some_dependency, int some_other_arg);
int some_type_init_state (const struct some_type *obj);
void some_type_release (const struct some_type *obj);
```

```
some_type_static.h

#define some_type_static_init(state_ptr, some_dependency_ptr, some_other_arg_arg)
```

## Virtual Functions

Virtual functions defined as part of an abstract type follow the same requirements for any function
of the module:
1. The first argument of the virtual function must be a pointer to the object instance that the
function will use for execution.
2. The instance pointer must be `const`.

When an object implements a virtual interface, it must provide an implementation for all functions.
It cannot leave any pointer NULL unless the base API is explicitly documented to allow optional
implementation, which should only be the case for observer event interfaces.  Modules that depend on
objects with a virtual interface assume the provided instance has been implemented and initialized
correctly and make no checks for valid function pointers before calling the interface.  Virtual
functions are  widely used throughout the code and making this kind of check prior to every call
would likely add significant code space to the final image.

## Error Codes

Every module will have a set of error codes associated with it that will uniquely identify error
conditions.

In the case of a derived type, the base type will have already defined a set of error codes that
would generally be used by the derived type.  If the derived type implementation generates
scenarios that the current set of errors codes doesn't sufficiently cover, the set of errors in the
base will be updated with the new error code.  Sometimes in this process, the error case needs to be
generalized a bit to make the error code reusable by other types or to not expose details of the
implementation.  In some cases, it's determined that it makes sense for the derived type to be a
separate module with its own set of error codes.  In this case, new error codes would be defined in
the same way for base and other non-derived types.

When defining a module that needs new error codes, there are some boilerplate pieces that need to be
there.
1. A new module ID needs to be assigned in `status\module_id.h`.
2. Error macros need to be defined in the module header file to generate error codes using the new
module ID.
3. An anonymous enum needs to be created that will define the error codes.
4. <MODULE>_INVALID_ARGUMENT gets assigned to code 0, within the module error space.  This is used
to report NULL argument or zero-length errors.  There may some other cases of invalid argument being
used, but most other parameter validation errors should be mapped to more specific error codes.
5. <MODULE>_NO_MEMORY get assigned to code 1, within the module error space.  This is used if a
dynamic memory allocation ever fails during execution.  This error number is reserved for this
purpose, even if the module doesn't use dynamic allocation.
6. If the module defines virtual functions, there needs to be a generic error code defined for each
function that can return an error.  This serves two purposes.  First, as a placeholder and general
error code that can be used by implementations of the function if other error codes are meaningful.
Second, as an error code that can be returned by mocks during unit testing.

After these pieces are satisfied, error codes can be assigned as desired.  Typically, they will be
assigned sequentially.

Once an error code has been defined for a module, it can never be reassigned for a different
purpose.  It can be deprecated by commenting it out from the enum (ensuring nothing uses it), but it
must remain in the header file to show what that error code maps to should it ever be encountered by
devices running older firmware images.

## Tests

All public APIs for the module must be fully unit tested through the module test suite.  This
includes implementations of any virtual functions as well as any module-specific functions that were
defined.  Tests should provide 100% code coverage and test all possible usage scenarios for each
API.  However, there are some specific scenarios where test code cannot generate coverage, such as
dynamic memory failures.

The unit test suite for the module must be included for execution in the unit test build.  This is
achieved by adding the module test suite in the appropriate `*_all_tests.h` file in the `testing`
sub-tree.  Each `*_all_tests.h` file within `testing` is responsible for adding the test suites
contained in that folder.  When new folders get added, a new `*_all_tests.h` needs to get added and
called from the `*_all_tests.h` file one level up in the hierarchy.

The unit test framework provides the ability to include or exclude specific modules from execution
at compile time, allowing targeted testing of a specific module or modules during development.  To
support this capability, the test suite associated for each module must be added to the
`*_all_tests.h` along with a standard set of conditionals.

```
#if (defined TESTING_RUN_SOME_OBJECT_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SOME_OBJECT_SUITE
	TESTING_RUN_SUITE (some_object);
#endif
```

Changing which unit test suites get executed leverages a `user_all_tests.h` file that defines macros
to enable or disable test suites.  If no `user_all_tests.h` file exists or the file exists but
doesn't define any macros, all tests suites are executed.  `user_all_tests.h` must be placed at a
location in the compiler's include path.  A best practice is to put the `user_all_tests.h` file in
the same location as the `platform_all_tests.h` file being used by the unit test build.

Each module will be associated with two macros to control execution of that specific test suite.
- TESTING_RUN_<module>_SUITE to enable execution of the module's test suite.
- TESTING_SKIP_<module>_SUITE to disable execution of the module's test suite.

Each project will have two macros associated with it to control execution off all tests suites
within that domain.  For the common Project Cerberus code, this project is `CORE`.
- TESTING_RUN_ALL_<project>_TESTS to enable execution of all project specific tests.
- TESTING_SKIP_ALL_<project>_TESTS to disable execution of all project specific tests.

At the top-level, all test suits can be globally enabled or disabled with two macros.
- TESTING_RUN_ALL_TESTS to enable all test suites across all projects.
- TESTING_SKIP_ALL_TESTS to disable all test suites across all projects.

In the case of conflicting macro definitions, the following priority is applied:
1. Skipping specific test suites
2. Running specific or global test suites
3. Skipping global test suites

For example, a `user_all_tests.h` with these contents can be used to run only the test suite for
`some_object`.

```
#define TESTING_SKIP_ALL_TESTS
#define TESTING_RUN_SOME_OBJECT_SUITE
```

With these contents, everything except the test suite for `some_object` will get executed.  There is
no need to explicitly define `TESTING_RUN_ALL_TESTS`.

```
#define TESTING_SKIP_SOME_OBJECT_SUITE
```

# Architecture and Design

The Cerberus code is architected for portability, testability, and reuse.  These are separate goals,
but are generally all achieved through different layers of abstraction.

## Portability

Most code is decoupled from device and platform specifics allowing it to be unit tested in a Linux
desktop environment.  This is achieved through a couple different mechanisms.
1. The `platform_api.h` abstraction layer is generally used to abstract system APIs or types
(e.g. `platform_mutex`) that often are part of the OS environment.  Each OS or device environment
(e.g. Linux, FreeRTOS) will provide an implementation of these API functions.
2. Abstract types for hardware drivers that can be mocked and used by other software components.

Individual components are designed to leave the minimal amount of code in the platform layer.  This
allows the maximum amount of code to be unit tested without needing specific hardware.  Having a
minimal platform port also makes that layer easier to manage.  It generally results in a smaller
amount of code, making different platform port simpler to generate.  The smaller code is also less
error-prone, which is good for layers that are often difficult to create unit tests for.

## Reuse and Flexibility

Dependencies between modules are provided during initialization, which allows different
implementations of abstract types to be used in different contexts.  Initialization of these
dependencies is left to management code, which ensures modules only interact through public APIs and
makes no assumptions about the specific type being used.  By relying on base interfaces, common
functionality can be developed that is independent of specific implementations or hardware, allowing
for more reuse.

Functions are implemented using object instances for execution context.  Everything that is needed
is part of either the constant or variable context in the object.  There is no reliance on global or
static variables.  Since all execution context is allocated and determined by top-level management
code, there is no need for special builds, swapping included files, or compilation flags to taylor
overall application execution.

There are some scenarios where static configuration is appropriate for a module, but more often any
information should be provided to the instance context.  This allows different application contexts
to define different parameters based on specific requirements.

## Testability

Testability is a primary goal of the architecture, but this is achieved naturally as a result of the
other architectural decisions.  Being portable allows the code to be easily run in many different
contexts, including Linux x64 environments.  Leveraging dependency injection and fully contained
execution contexts allows mock instances to easily be used in testing contexts.

When testing a particular module, dependencies should be mocked as much as possible.  This limits
test suite dependencies and makes test cases leaner and easier to understand and maintain.  Without
mocks, multiple levels of dependencies would need to be initialized.  At some point, these
dependencies would likely reach a layer that needs to mocked, which could be so far removed from the
module under test that the mock becomes less obvious.  Additionally, taking multiple layers of
dependencies makes test suites more likely to be impacted by changes in the code base.  By limiting
the dependencies to mocks, only changes to the API definition or functionality would impact test
suites.

# Implementation

While implementation details will vary a lot between different modules and contexts, there are a few
general approaches that should be followed.

## Test Driven Development (TDD)

All code is expected to be developed following TDD.
- Before any code for any module is written, there should be a test case that requires that code to
be there.
- Only write the minimum amount of code to get the test case to pass.  Once passing, write a new
test case to cover additional scenarios.

Each test scenario should be its own test case.  Grouping multiple different scenarios into single
test cases makes it more difficult to look at the test suite and see what scenarios are covered and
where.

Helper functions can (and should) be used for initializing multiple dependencies, setting up the
instance for the test case, and handling complex, reusable mock sequences.  However, overuse of
helper functions should be avoided, as it starts to make the individual test cases more opaque and
harder to understand.  In general, test cases don't need to be highly optimized.

## Avoid Duplicate Code

New modules, particularly when deriving from existing types, should leverage as much existing
functionality as possible.  Copying functions into related modules should be avoided in favor of
refactoring commonalities into shared functions.  Sometimes this means removing `static` from
function definitions and exposing them as 'internal' functions in the base type's header file.

When defining new functionality, effort should be made to understand if it overlaps with existing
functionality and how to best leverage that commonality.

Do not treat code as immutable.  It's generally expected that modules will get refactored and/or
expanded as additional functionality is needed.  Following TDD and having extensive unit tests really
helps in this regard.  By having full test coverage of functionality of public APIs, it can be shown
that refactoring hasn't changed any API behavior when test cases continue to pass as expected.

## Compile Switches

Use of compile switches should be used sparingly in the code.  Overuse of compile switches within
execution flows can quickly make confusing code that is difficult to maintain and test.  Achieving
different behavior for different situations should primarily be done by different object types that
can be instantiated to get the desired behavior.

The current use of compile switches generally falls into two categories:
1. Settings to enable certain functions of an API or features of the system.  The motivation for
these was primarily to reduce code space by removing unneeded virtual functions that would otherwise
not get optimized out of the compiled code.  While this approach has been used in the past to
achieve this goal, the same could likely have been accomplished with some refactoring and separation
of types.  Future additions should prefer to refactor or define new types rather than adding new
compile switches.
2. Global configuration parameters that apply to the target platform, which are defined in the
`platform_config.h` file for the target.  These should be settings that apply universally to a
platform and are often used to define sizes of buffers or types.  However, where feasible, passing
user-defined buffers as init-time arguments with a specified length should be preferred over static
buffer sizes defined through compile-time defines.  This approach allows for different instances of
the same type with different usage requirements to be allocated buffers of different sizes.

In the end, compile switches can be used when they make sense, but their use should be intentional
and thoughtful rather than a default option.  Many current use-cases could (and probably should)
have been handled without compile-time macros, so following existing patterns shouldn't be done
blindly.

## Dynamic Memory Allocation

Dynamic memory allocation should be used sparingly.  There are certainly scenarios where dynamic
allocation make sense, but there are plenty more where static allocation is a better choice.
Historically, there was more liberal use of dynamic allocation in the code base, but this resulted
in code that was harder to track overall memory usage and had more potential points of failure.
Target applications are typically expected to have a static configuration of types and resources
that are all allocated during initialization.  Having a clear picture of how much memory is needed
to achieve that configuration at compile time is valuable.  This type of allocation is also not
always compatible with constant static instances.

There has been ongoing effort to reduce dynamic allocation usage, especially during object
initialization, so new modules should follow this same pattern.  It's acceptable to have an
initialization option that uses dynamic allocation, but there should always be a static allocation
option, too.

# Agreement and Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact
[opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
