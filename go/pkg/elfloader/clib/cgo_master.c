// Master C file for CGO compilation
// This prevents multiple definition errors by having a single compilation unit

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

// Prevent beacon_compatibility.h from being included
#define BEACON_COMPATIBILITY_H_

// Forward declarations of Go-exported functions
extern void GoBeaconPrintf(int type, char* message);
extern void GoBeaconFormatPrintf(void* format, char* message);

// Variadic wrappers for BeaconPrintf and BeaconFormatPrintf
void BeaconPrintf(int type, const char* fmt, ...) {
    char buffer[8192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    GoBeaconPrintf(type, buffer);
}

void BeaconFormatPrintf(void* format, const char* fmt, ...) {
    char buffer[8192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    GoBeaconFormatPrintf(format, buffer);
}

// Forward declare what ELFLoader.c needs
void* internalFunctionLookup(char* symbolName);

// Include all C sources in the correct order
#include "c_internal_funcs.c.inc"      // Provides internalFunctionLookup
#include "../../../src/ELFLoader.c"     // Main ELF loader
#include "c_loader_wrapper.c.inc"      // Wrapper for Go to call
