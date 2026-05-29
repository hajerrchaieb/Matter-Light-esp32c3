/**
 * test_runtime/host_main.cpp
 * ===========================
 * Bridge between a real Linux process and the embedded-style
 * `app_main()` entry point that agents/test_gen_agent.py emits at
 * the bottom of every generated test file.
 */

#include <cstdio>
#include "unity.h"

/* `app_main` is defined in the generated test file as a regular
 * C++ function (no extern "C"). We just declare it the same way. */
void app_main(void);

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    fprintf(stdout, "\n[host-runner] Invoking app_main()...\n");
    fflush(stdout);

    app_main();

    fprintf(stdout,
        "\n[host-runner] app_main returned. "
        "tests=%d failed=%d\n",
        unity_total_tests, unity_total_failed);
    fflush(stdout);

    if (unity_total_failed > 255) return 255;
    return unity_total_failed;
}
