/* TEST-ONLY native fixture engine for GOAT v0.4.0 updater tests.
 *
 * This program is compiled on-demand by the native health test. It is not a
 * real GOAT engine and must never be shipped in the goatcli package.
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    /* The exact version string must match the health check's expectedVersion. */
    printf("0.4.0\n");
    return 0;
  }
  return 1;
}
