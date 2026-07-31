/* TEST-ONLY native fixture engine for GOAT v0.4.0 updater tests.
 *
 * This program is compiled on-demand by the native health test. It is not a
 * real GOAT engine and must never be shipped in the goatcli package.
 */

#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    /* The exact version string must match the health check's expectedVersion. */
    printf("0.4.0\n");
    return 0;
  }
  if (argc == 2 && strcmp(argv[1], "--hold") == 0) {
    /* Keep the process (and its executable image) alive so tests can observe
       locked-file behavior on Windows. */
    while (1) {
#ifdef _WIN32
      Sleep(1000);
#else
      sleep(1);
#endif
    }
    return 0;
  }
  return 1;
}
