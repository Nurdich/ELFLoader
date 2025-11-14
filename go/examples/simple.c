#include <stdio.h>

// Simple test function
int go(unsigned char* args, int len) {
    printf("=== Go ELF Loader - Execution Test ===\n");
    printf("Successfully executed loaded ELF code!\n");
    printf("Arguments length: %d\n", len);

    if (args != NULL && len > 0) {
        printf("First argument byte: 0x%02x\n", args[0]);
    }

    printf("Test PASSED!\n");
    fflush(stdout);
    return 42;  // Return a distinctive value
}
