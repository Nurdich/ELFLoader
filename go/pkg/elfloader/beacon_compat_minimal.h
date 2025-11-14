/*
 * Minimal beacon compatibility header for CGO integration
 * Only declares what's needed by ELFLoader.c
 */
#ifndef BEACON_COMPAT_MINIMAL_H_
#define BEACON_COMPAT_MINIMAL_H_

// Forward declaration of internal function lookup
// Actual implementation is in c_internal_funcs.c which bridges to Go
void* internalFunctionLookup(char* symbolName);

#endif
