/**
 * test_runtime/unity.h
 * ====================
 * Minimal Unity-compatible test framework for host-side execution.
 *
 * State variables are declared extern here and DEFINED in unity.c.
 */

#ifndef UNITY_H
#define UNITY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* State, defined in unity.c */
extern int unity_total_tests;
extern int unity_total_failed;
extern int unity_total_ignored;
extern int unity_current_failed;
extern const char *unity_current_test;

/* setUp / tearDown — provided by the test file */
void setUp(void);
void tearDown(void);

#ifdef __cplusplus
}
#endif

#define UNITY_BEGIN()  do {                                 \
    unity_total_tests = 0;                                  \
    unity_total_failed = 0;                                 \
    unity_total_ignored = 0;                                \
    printf("\n----- UNITY TEST SUITE START -----\n");       \
} while(0)

#define UNITY_END()  ({                                     \
    printf("\n-----------------------\n");                  \
    printf("%d Tests %d Failures %d Ignored\n",             \
           unity_total_tests,                               \
           unity_total_failed,                              \
           unity_total_ignored);                            \
    printf(unity_total_failed == 0 ? "OK\n" : "FAIL\n");    \
    unity_total_failed;                                     \
})

#define RUN_TEST(fn)  do {                                  \
    unity_total_tests++;                                    \
    unity_current_failed = 0;                               \
    unity_current_test = #fn;                               \
    setUp();                                                \
    fn();                                                   \
    tearDown();                                             \
    if (!unity_current_failed) {                            \
        printf("%s:%d:%s:PASS\n",                           \
               __FILE__, __LINE__, #fn);                    \
    }                                                       \
} while(0)

#define UNITY_FAIL_AT(line, msg)  do {                      \
    unity_current_failed = 1;                               \
    unity_total_failed++;                                   \
    printf("%s:%d:%s:FAIL: %s\n",                           \
           __FILE__, line, unity_current_test, msg);        \
} while(0)

#define TEST_ASSERT_EQUAL(expected, actual)  do {           \
    long long _e = (long long)(expected);                   \
    long long _a = (long long)(actual);                     \
    if (_e != _a) {                                         \
        char _msg[128];                                     \
        snprintf(_msg, sizeof(_msg),                        \
                 "Expected %lld Was %lld", _e, _a);         \
        UNITY_FAIL_AT(__LINE__, _msg);                      \
        return;                                             \
    }                                                       \
} while(0)

#define TEST_ASSERT_EQUAL_INT  TEST_ASSERT_EQUAL
#define TEST_ASSERT_EQUAL_UINT TEST_ASSERT_EQUAL

#define TEST_ASSERT_NOT_NULL(ptr)  do {                     \
    if ((ptr) == NULL) {                                    \
        UNITY_FAIL_AT(__LINE__, "Expected non-NULL");       \
        return;                                             \
    }                                                       \
} while(0)

#define TEST_ASSERT_NULL(ptr)  do {                         \
    if ((ptr) != NULL) {                                    \
        UNITY_FAIL_AT(__LINE__, "Expected NULL");           \
        return;                                             \
    }                                                       \
} while(0)

#define TEST_ASSERT_TRUE(cond)  do {                        \
    if (!(cond)) {                                          \
        UNITY_FAIL_AT(__LINE__, "Expected TRUE");           \
        return;                                             \
    }                                                       \
} while(0)

#define TEST_ASSERT_FALSE(cond)  do {                       \
    if ((cond)) {                                           \
        UNITY_FAIL_AT(__LINE__, "Expected FALSE");          \
        return;                                             \
    }                                                       \
} while(0)

#define TEST_PASS()    do { return; } while(0)

#define TEST_IGNORE()  do {                                 \
    unity_total_ignored++;                                  \
    printf("%s:%d:%s:IGNORE\n",                             \
           __FILE__, __LINE__, unity_current_test);         \
    return;                                                 \
} while(0)

#endif /* UNITY_H */
