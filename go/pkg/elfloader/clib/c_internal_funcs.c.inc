// c_internal_funcs.c
// Provide internalFunctionLookup implementation that calls back to Go

#include <string.h>
#include <dlfcn.h>

// Forward declarations for Go-exported Beacon API functions
extern void BeaconDataParse(void* parser, unsigned char* buffer, int size);
extern int BeaconDataInt(void* parser);
extern short BeaconDataShort(void* parser);
extern int BeaconDataLength(void* parser);
extern unsigned char* BeaconDataExtract(void* parser, int* outsize);
extern void BeaconFormatAlloc(void* format, int maxsz);
extern void BeaconFormatReset(void* format);
extern void BeaconFormatFree(void* format);
extern void BeaconFormatAppend(void* format, unsigned char* text, int len);
extern void BeaconFormatPrintf(void* format, const char* fmt, ...);
extern unsigned char* BeaconFormatToString(void* format, int* outsize);
extern void BeaconFormatInt(void* format, int value);
extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, unsigned char* data, int len);
extern int BeaconIsAdmin(void);
extern char** getEnviron(void);
extern char* getOSName(void);

// Internal function lookup table for Beacon API
typedef struct {
    const char* name;
    void* ptr;
} FunctionMapping;

static FunctionMapping function_table[] = {
    {"BeaconDataParse", (void*)BeaconDataParse},
    {"BeaconDataInt", (void*)BeaconDataInt},
    {"BeaconDataShort", (void*)BeaconDataShort},
    {"BeaconDataLength", (void*)BeaconDataLength},
    {"BeaconDataExtract", (void*)BeaconDataExtract},
    {"BeaconFormatAlloc", (void*)BeaconFormatAlloc},
    {"BeaconFormatReset", (void*)BeaconFormatReset},
    {"BeaconFormatFree", (void*)BeaconFormatFree},
    {"BeaconFormatAppend", (void*)BeaconFormatAppend},
    {"BeaconFormatPrintf", (void*)BeaconFormatPrintf},
    {"BeaconFormatToString", (void*)BeaconFormatToString},
    {"BeaconFormatInt", (void*)BeaconFormatInt},
    {"BeaconPrintf", (void*)BeaconPrintf},
    {"BeaconOutput", (void*)BeaconOutput},
    {"BeaconIsAdmin", (void*)BeaconIsAdmin},
    {"getEnviron", (void*)getEnviron},
    {"getOSName", (void*)getOSName},
    {NULL, NULL}
};

// Implementation of internalFunctionLookup that ELFLoader.c will use
void* internalFunctionLookup(char* symbolName) {
    // First check our internal function table
    for (int i = 0; function_table[i].name != NULL; i++) {
        if (strcmp(symbolName, function_table[i].name) == 0) {
            return function_table[i].ptr;
        }
    }

    // If not found in internal table, try dlsym for system functions
    void* handle = NULL; // RTLD_DEFAULT on Linux
    void* ptr = dlsym(handle, symbolName);
    return ptr;
}
