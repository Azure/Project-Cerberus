// Portions Copyright (c) Microsoft Corporation

#include <stdio.h>

#include "CuTest.h"
#include "all_tests.h"


int RunAllTests (void)
{
	CuString *output = CuStringNew ();
	CuSuite *suite = CuSuiteNew ();
	int fail;

	add_all_tests (suite);

	setvbuf (stdout, NULL, _IONBF, 0);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	fail = suite->failCount;

	CuStringDelete (output);
	CuSuiteDelete (suite);
	return fail;
}

int main (void)
{
	return RunAllTests ();
}
