// beacon_variadic.c
// C wrappers for variadic Beacon API functions

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Forward declaration of Go export that handles the actual printing
extern void GoBeaconPrintf(int type, char* message);
extern void GoBeaconFormatPrintf(void* format, char* message);

// Variadic wrapper for BeaconPrintf
void BeaconPrintf(int type, const char* fmt, ...) {
    char buffer[8192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    GoBeaconPrintf(type, buffer);
}

// Variadic wrapper for BeaconFormatPrintf
void BeaconFormatPrintf(void* format, const char* fmt, ...) {
    char buffer[8192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    GoBeaconFormatPrintf(format, buffer);
}
