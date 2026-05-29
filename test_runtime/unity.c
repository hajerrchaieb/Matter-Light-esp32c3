/**
 * test_runtime/unity.c
 * ====================
 * Single definition site for Unity host runner state.
 * Compiled into the host test binary alongside the generated test
 * file and host_main.cpp.
 */

#include "unity.h"

int unity_total_tests    = 0;
int unity_total_failed   = 0;
int unity_total_ignored  = 0;
int unity_current_failed = 0;
const char *unity_current_test = "";
