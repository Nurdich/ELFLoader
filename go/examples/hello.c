#include <stdio.h>

// Entry point function - must be named "go"
int go(unsigned char* args, int len) {
    printf("Hello from ELF Loader (Go version)!\n");
    printf("Architecture: %s\n",
#ifdef __x86_64__
        "x86_64"
#elif __i386__
        "x86"
#else
        "unknown"
#endif
    );

    if (args != NULL && len > 0) {
        printf("Received %d bytes of arguments\n", len);
        printf("Arguments: ");
        for (int i = 0; i < len && i < 64; i++) {
            printf("%02x ", args[i]);
        }
        printf("\n");
    }

    return 0;
}
