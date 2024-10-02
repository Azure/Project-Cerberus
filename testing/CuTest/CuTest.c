// Portions Copyright (c) Microsoft Corporation

#include "CuTest.h"

#include <assert.h>
#include <math.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform_io.h"


/*-------------------------------------------------------------------------*
 * CuStr
 *-------------------------------------------------------------------------*/

char* CuStrAlloc (int size)
{
	char *newStr = (char*) platform_malloc (sizeof (char) * (size));

	return newStr;
}

char* CuStrCopy (const char *old)
{
	int len = strlen (old);
	char *newStr = CuStrAlloc (len + 1);

	strcpy (newStr, old);

	return newStr;
}

/*-------------------------------------------------------------------------*
 * CuString
 *-------------------------------------------------------------------------*/

void CuStringInit (CuString *str)
{
	str->length = 0;
	str->size = STRING_MAX;
	str->buffer = (char*) platform_malloc (sizeof (char) * str->size);
	str->buffer[0] = '\0';
}

CuString* CuStringNew (void)
{
	CuString *str = (CuString*) platform_malloc (sizeof (CuString));

	str->length = 0;
	str->size = STRING_MAX;
	str->buffer = (char*) platform_malloc (sizeof (char) * str->size);
	str->buffer[0] = '\0';

	return str;
}

void CuStringDelete (CuString *str)
{
	if (!str) {
		return;
	}
	platform_free (str->buffer);
	platform_free (str);
}

void CuStringResize (CuString *str, int newSize)
{
	str->buffer = (char*) platform_realloc (str->buffer, sizeof (char) * newSize);
	str->size = newSize;
}

void CuStringAppend (CuString *str, const char *text)
{
	int length;

	if (text == NULL) {
		text = "NULL";
	}

	length = strlen (text);
	if (str->length + length + 1 >= str->size) {
		CuStringResize (str, str->length + length + 1 + STRING_INC);
	}
	str->length += length;
	strcat (str->buffer, text);
}

void CuStringAppendChar (CuString *str, char ch)
{
	char text[2];

	text[0] = ch;
	text[1] = '\0';
	CuStringAppend (str, text);
}

void CuStringAppendFormat (CuString *str, const char *format, ...)
{
	va_list argp;
	char buf[HUGE_STRING_LEN];

	va_start (argp, format);
	vsprintf (buf, format, argp);
	va_end (argp);
	CuStringAppend (str, buf);
}

void CuStringInsert (CuString *str, const char *text, int pos)
{
	int length = strlen (text);

	if (pos > str->length) {
		pos = str->length;
	}
	if (str->length + length + 1 >= str->size) {
		CuStringResize (str, str->length + length + 1 + STRING_INC);
	}
	memmove (str->buffer + pos + length, str->buffer + pos, (str->length - pos) + 1);
	str->length += length;
	memcpy (str->buffer + pos, text, length);
}

/*-------------------------------------------------------------------------*
 * CuTest
 *-------------------------------------------------------------------------*/

void CuTestInit (CuTest *t, const char *name, TestFunction function)
{
	if (!t) {
		return;
	}
	t->name = CuStrCopy (name);
	t->failed = 0;
	t->ran = 0;
	t->message = NULL;
	t->function = function;
	t->jumpBuf = NULL;
}

CuTest* CuTestNew (const char *name, TestFunction function)
{
	CuTest *tc = CU_ALLOC (CuTest);

	CuTestInit (tc, name, function);

	return tc;
}

void CuTestDelete (CuTest *t)
{
	if (!t) {
		return;
	}
	CuStringDelete (t->message);
	platform_free (t->name);
	platform_free (t);
}

void CuTestRun (CuTest *tc)
{
	jmp_buf buf;

	tc->jumpBuf = &buf;
	if (setjmp (buf) == 0) {
		tc->ran = 1;
		(tc->function) (tc);
	}
	tc->jumpBuf = 0;
}

static void CuFailInternal (CuTest *tc, const char *file, int line, CuString *string)
{
	char buf[HUGE_STRING_LEN];

	sprintf (buf, "%s:%d: ", file, line);
	CuStringInsert (string, buf, 0);

	tc->failed = 1;
	platform_free (tc->message);
	tc->message = CuStringNew ();
	CuStringAppend (tc->message, string->buffer);
	if (tc->jumpBuf != 0) {
		longjmp (*(tc->jumpBuf), 0);
	}
}

void CuFail_Line (CuTest *tc, const char *file, int line, const char *message2, const char *message)
{
	CuString string;

	CuStringInit (&string);
	if (message2 != NULL) {
		CuStringAppend (&string, message2);
		CuStringAppend (&string, ": ");
	}
	CuStringAppend (&string, message);
	CuFailInternal (tc, file, line, &string);
}

void CuAssert_Line (CuTest *tc, const char *file, int line, const char *message, int condition)
{
	if (condition) {
		return;
	}
	CuFail_Line (tc, file, line, NULL, message);
}

void CuAssertStrEquals_LineMsg (CuTest *tc, const char *file, int line, const char *message,
	const char *expected, const char *actual)
{
	CuString string;

	if (((expected == NULL) && (actual == NULL)) ||
		((expected != NULL) && (actual != NULL) &&
		(strcmp (expected, actual) == 0))) {
		return;
	}

	CuStringInit (&string);
	if (message != NULL) {
		CuStringAppend (&string, message);
		CuStringAppend (&string, ": ");
	}
	CuStringAppend (&string, "expected [");
	CuStringAppend (&string, expected);
	CuStringAppend (&string, "] but was [");
	CuStringAppend (&string, actual);
	CuStringAppend (&string, "]");
	CuFailInternal (tc, file, line, &string);
}

void CuAssertIntEquals_LineMsg (CuTest *tc, const char *file, int line, const char *message,
	int expected, int actual)
{
	char buf[STRING_MAX];

	if (expected == actual) {
		return;
	}
	sprintf (buf, "expected [%d] but was [%d]", expected, actual);
	CuFail_Line (tc, file, line, message, buf);
}

void CuAssertInt64Equals_LineMsg (CuTest *tc, const char *file, int line, const char *message,
	long long expected, long long actual)
{
	char buf[STRING_MAX];

	if (expected == actual) {
		return;
	}
	sprintf (buf, "expected [%lld] but was [%lld]", expected, actual);
	CuFail_Line (tc, file, line, message, buf);
}

void CuAssertDblEquals_LineMsg (CuTest *tc, const char *file, int line, const char *message,
	double expected, double actual, double delta)
{
	char buf[STRING_MAX];

	if (fabs (expected - actual) <= delta) {
		return;
	}
	sprintf (buf, "expected [%f] but was [%f]", expected, actual);

	CuFail_Line (tc, file, line, message, buf);
}

void CuAssertPtrEquals_LineMsg (CuTest *tc, const char *file, int line, const char *message,
	const void *expected, const void *actual)
{
	char buf[STRING_MAX];

	if (expected == actual) {
		return;
	}
	sprintf (buf, "expected pointer [0x%p] but was [0x%p]", expected, actual);
	CuFail_Line (tc, file, line, message, buf);
}


/*-------------------------------------------------------------------------*
 * CuSuite
 *-------------------------------------------------------------------------*/

void CuSuiteInit (CuSuite *testSuite)
{
	if (!testSuite) {
		return;
	}
	testSuite->count = 0;
	testSuite->failCount = 0;
	memset (testSuite->list, 0, sizeof (testSuite->list));
}

CuSuite* CuSuiteNew (void)
{
	CuSuite *testSuite = CU_ALLOC (CuSuite);

	CuSuiteInit (testSuite);

	return testSuite;
}

void CuSuiteDelete (CuSuite *testSuite)
{
	unsigned int n;

	if (!testSuite) {
		return;
	}
	for (n = 0; n < MAX_TEST_CASES; n++) {
		if (testSuite->list[n])	{
			CuTestDelete (testSuite->list[n]);
		}
	}
	platform_free (testSuite);
}

void CuSuiteAdd (CuSuite *testSuite, CuTest *testCase)
{
	assert (testSuite->count < MAX_TEST_CASES);
	testSuite->list[testSuite->count] = testCase;
	testSuite->count++;
}

void CuSuiteAddSuite (CuSuite *testSuite, CuSuite *testSuite2)
{
	int i;

	for (i = 0; i < testSuite2->count; ++i)	{
		CuTest *testCase = testSuite2->list[i];

		CuSuiteAdd (testSuite, testCase);
	}
	platform_free (testSuite2);
}

void CuSuiteRun (CuSuite *testSuite)
{
	int i;

	for (i = 0; i < testSuite->count; ++i) {
		CuTest *testCase = testSuite->list[i];

		CuTestRun (testCase);
		if (testCase->failed) {
			testSuite->failCount += 1;
		}
	}
}

void CuSuiteSummary (CuSuite *testSuite, CuString *summary)
{
	int i;

	for (i = 0; i < testSuite->count; ++i) {
		CuTest *testCase = testSuite->list[i];

		platform_CuStringAppend (summary, testCase->failed ? "F" : ".");
	}
	platform_CuStringAppend (summary, NEWLINE NEWLINE);
}

void CuSuiteDetails (CuSuite *testSuite, CuString *details)
{
	int i;
	int failCount = 0;

	if (testSuite->failCount == 0) {
		int passCount = testSuite->count - testSuite->failCount;
		const char *testWord = (passCount == 1) ? "test" : "tests";

		platform_CuStringAppendFormat (details, "OK (%d %s)" NEWLINE, passCount, testWord);
	}
	else {
		if (testSuite->failCount == 1) {
			platform_CuStringAppend (details, "There was 1 failure:" NEWLINE);
		}
		else {
			platform_CuStringAppendFormat (details, "There were %d failures:" NEWLINE,
				testSuite->failCount);
		}

		for (i = 0; i < testSuite->count; ++i) {
			CuTest *testCase = testSuite->list[i];

			if (testCase->failed) {
				failCount++;
				platform_CuStringAppendFormat (details, "%d) %s: %s" NEWLINE, failCount,
					testCase->name, testCase->message->buffer);
			}
		}
		platform_CuStringAppend (details, NEWLINE "!!!FAILURES!!!" NEWLINE);

		platform_CuStringAppendFormat (details, "Runs: %d ", testSuite->count);
		platform_CuStringAppendFormat (details, "Passes: %d ",
			testSuite->count - testSuite->failCount);
		platform_CuStringAppendFormat (details, "Fails: %d" NEWLINE, testSuite->failCount);
	}
}

void CuSuiteToJUnitXML (CuSuite *testSuite, CuString *report)
{
	int i;

	// XML header and suite information
	platform_CuStringAppend (report, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" NEWLINE);
	platform_CuStringAppendFormat (report,
		"<testsuite name=\"CuTest\" tests=\"%d\" failures=\"%d\" errors=\"%d\">" NEWLINE,
		testSuite->count, testSuite->failCount, testSuite->failCount);

	for (i = 0; i < testSuite->count; ++i) {
		CuTest *testCase = testSuite->list[i];

		platform_CuStringAppendFormat (report, "    <testcase classname=\"CuTest\" name=\"%s\">",
			testCase->name);

		if (testCase->failed) {
			platform_CuStringAppendFormat (report, NEWLINE "        <failure>%s</failure>" NEWLINE,
				testCase->message->buffer);
		}
		platform_CuStringAppend (report, "    </testcase>" NEWLINE);
	}

	platform_CuStringAppend (report, "</testsuite>" NEWLINE);
}
