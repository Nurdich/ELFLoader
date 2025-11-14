package elfloader

import (
	"debug/elf"
	"fmt"
	"plugin"
	"runtime"
	"unsafe"
)

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// Forward declarations for Go CGO exports
extern void GoBeaconPrintf(int type, char* message);
extern void GoBeaconFormatPrintf(void* format, char* message);
extern void BeaconDataParse(void* parser, unsigned char* buffer, int size);
extern int BeaconDataInt(void* parser);
extern short BeaconDataShort(void* parser);
extern int BeaconDataLength(void* parser);
extern unsigned char* BeaconDataExtract(void* parser, int* outsize);
extern void BeaconFormatAlloc(void* format, int maxsz);
extern void BeaconFormatReset(void* format);
extern void BeaconFormatFree(void* format);
extern void BeaconFormatAppend(void* format, unsigned char* text, int len);
extern unsigned char* BeaconFormatToString(void* format, int* outsize);
extern void BeaconFormatInt(void* format, int value);
extern void BeaconOutput(int type, unsigned char* data, int len);
extern int BeaconIsAdmin(void);
extern char** getEnviron(void);
extern char* getOSName(void);

// Variadic wrappers for BeaconPrintf and BeaconFormatPrintf
// These must NOT be static or inline so they have real addresses in the binary
void BeaconPrintf_wrapper(int type, const char* fmt, ...) {
    char buffer[8192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    GoBeaconPrintf(type, buffer);
}

void BeaconFormatPrintf_wrapper(void* format, const char* fmt, ...) {
    char buffer[8192];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    GoBeaconFormatPrintf(format, buffer);
}

// For compatibility, redirect to the wrapper functions
#define BeaconPrintf BeaconPrintf_wrapper
#define BeaconFormatPrintf BeaconFormatPrintf_wrapper

// Helper functions to get function pointers
static inline void* get_BeaconPrintf_ptr() { return (void*)BeaconPrintf; }
static inline void* get_BeaconDataParse_ptr() { return (void*)BeaconDataParse; }
static inline void* get_BeaconDataInt_ptr() { return (void*)BeaconDataInt; }
static inline void* get_BeaconDataShort_ptr() { return (void*)BeaconDataShort; }
static inline void* get_BeaconDataLength_ptr() { return (void*)BeaconDataLength; }
static inline void* get_BeaconDataExtract_ptr() { return (void*)BeaconDataExtract; }
static inline void* get_BeaconFormatAlloc_ptr() { return (void*)BeaconFormatAlloc; }
static inline void* get_BeaconFormatReset_ptr() { return (void*)BeaconFormatReset; }
static inline void* get_BeaconFormatFree_ptr() { return (void*)BeaconFormatFree; }
static inline void* get_BeaconFormatAppend_ptr() { return (void*)BeaconFormatAppend; }
static inline void* get_BeaconFormatPrintf_ptr() { return (void*)BeaconFormatPrintf; }
static inline void* get_BeaconFormatToString_ptr() { return (void*)BeaconFormatToString; }
static inline void* get_BeaconFormatInt_ptr() { return (void*)BeaconFormatInt; }
static inline void* get_BeaconOutput_ptr() { return (void*)BeaconOutput; }
static inline void* get_BeaconIsAdmin_ptr() { return (void*)BeaconIsAdmin; }
static inline void* get_getEnviron_ptr() { return (void*)getEnviron; }
static inline void* get_getOSName_ptr() { return (void*)getOSName; }
*/
import "C"

// InternalFunction represents an internal API function
type InternalFunction struct {
	Name string
	Ptr  uintptr
}

// GetInternalFunctions returns the list of internal Beacon API functions
func GetInternalFunctions() []InternalFunction {
	// Get addresses of CGO-exported functions using C function pointers
	// This ensures we get the correct absolute addresses
	return []InternalFunction{
		{"BeaconDataParse", uintptr(C.get_BeaconDataParse_ptr())},
		{"BeaconDataInt", uintptr(C.get_BeaconDataInt_ptr())},
		{"BeaconDataShort", uintptr(C.get_BeaconDataShort_ptr())},
		{"BeaconDataLength", uintptr(C.get_BeaconDataLength_ptr())},
		{"BeaconDataExtract", uintptr(C.get_BeaconDataExtract_ptr())},
		{"BeaconFormatAlloc", uintptr(C.get_BeaconFormatAlloc_ptr())},
		{"BeaconFormatReset", uintptr(C.get_BeaconFormatReset_ptr())},
		{"BeaconFormatFree", uintptr(C.get_BeaconFormatFree_ptr())},
		{"BeaconFormatAppend", uintptr(C.get_BeaconFormatAppend_ptr())},
		{"BeaconFormatPrintf", uintptr(C.get_BeaconFormatPrintf_ptr())},
		{"BeaconFormatToString", uintptr(C.get_BeaconFormatToString_ptr())},
		{"BeaconFormatInt", uintptr(C.get_BeaconFormatInt_ptr())},
		{"BeaconPrintf", uintptr(C.get_BeaconPrintf_ptr())},
		{"BeaconOutput", uintptr(C.get_BeaconOutput_ptr())},
		{"BeaconIsAdmin", uintptr(C.get_BeaconIsAdmin_ptr())},
		{"getEnviron", uintptr(C.get_getEnviron_ptr())},
		{"getOSName", uintptr(C.get_getOSName_ptr())},
	}
}

// resolveSymbol resolves a symbol to its address
func resolveSymbol(info *ELFInfo, sym *elf.Symbol) (uintptr, error) {
	// Handle special symbols
	if sym.Name == "_GLOBAL_OFFSET_TABLE_" || sym.Name == "_DYNAMIC" {
		// These are special linker symbols that are not needed for object files
		// Return a dummy address
		return uintptr(0), nil
	}

	// If symbol is in a section, calculate its address
	if sym.Section != elf.SHN_UNDEF {
		if int(sym.Section) >= len(info.SectionMappings) {
			return 0, fmt.Errorf("symbol section index out of range")
		}
		baseAddr := info.SectionMappings[sym.Section]
		return baseAddr + uintptr(sym.Value), nil
	}

	// Symbol is undefined - look it up externally
	return lookupExternalSymbol(sym.Name)
}

// lookupExternalSymbol looks up an external symbol (libc or internal)
func lookupExternalSymbol(name string) (uintptr, error) {
	// First check internal functions
	for _, fn := range GetInternalFunctions() {
		if fn.Name == name {
			return fn.Ptr, nil
		}
	}

	// Try to resolve from libc using dlsym
	return dlsymLookup(name)
}

// dlsymLookup looks up a symbol using dlsym
func dlsymLookup(name string) (uintptr, error) {
	// Use RTLD_DEFAULT to search in the global symbol table
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	// RTLD_DEFAULT on different platforms
	var handle unsafe.Pointer
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd":
		handle = unsafe.Pointer(uintptr(0xfffffffffffffffe)) // RTLD_DEFAULT
	case "linux":
		handle = nil // RTLD_DEFAULT on Linux
	default:
		return 0, fmt.Errorf("unsupported OS for dlsym: %s", runtime.GOOS)
	}

	ptr := C.dlsym(handle, cname)
	if ptr == nil {
		return 0, fmt.Errorf("symbol not found: %s", name)
	}

	return uintptr(ptr), nil
}

// createThunkTrampoline creates a thunk trampoline for calling external functions
func createThunkTrampoline(info *ELFInfo, targetAddr uintptr) (uintptr, error) {
	var trampoline []byte
	var offset int

	switch runtime.GOARCH {
	case "amd64":
		trampoline = make([]byte, len(ThunkTrampoline64))
		copy(trampoline, ThunkTrampoline64)
		offset = ThunkOffset64
		// Write target address into trampoline
		writeUint64ToBytes(trampoline[offset:], uint64(targetAddr))

	case "386":
		trampoline = make([]byte, len(ThunkTrampoline32))
		copy(trampoline, ThunkTrampoline32)
		offset = ThunkOffset32
		// Write target address into trampoline
		writeUint32ToBytes(trampoline[offset:], uint32(targetAddr))

	default:
		return 0, fmt.Errorf("unsupported architecture for thunk: %s", runtime.GOARCH)
	}

	// Calculate trampoline address in the thunk table
	thunkSize := getThunkTrampolineSize()
	thunkAddr := info.TempOffsetTable + uintptr(info.TempOffsetCounter*thunkSize)

	// Copy trampoline to the thunk table
	copyToAddr(thunkAddr, trampoline)

	// Increment counter
	info.TempOffsetCounter++

	return thunkAddr, nil
}


// writeUint32ToBytes writes a uint32 to a byte slice in little-endian
func writeUint32ToBytes(data []byte, value uint32) {
	data[0] = byte(value)
	data[1] = byte(value >> 8)
	data[2] = byte(value >> 16)
	data[3] = byte(value >> 24)
}

// writeUint64ToBytes writes a uint64 to a byte slice in little-endian
func writeUint64ToBytes(data []byte, value uint64) {
	data[0] = byte(value)
	data[1] = byte(value >> 8)
	data[2] = byte(value >> 16)
	data[3] = byte(value >> 24)
	data[4] = byte(value >> 32)
	data[5] = byte(value >> 40)
	data[6] = byte(value >> 48)
	data[7] = byte(value >> 56)
}

// Alternative symbol lookup using plugin (Go-only, limited use)
func lookupSymbolViaPlugin(name string) (uintptr, error) {
	// This is primarily for demonstration - plugins are limited in Go
	p, err := plugin.Open("")
	if err != nil {
		return 0, err
	}

	sym, err := p.Lookup(name)
	if err != nil {
		return 0, err
	}

	return uintptr(unsafe.Pointer(&sym)), nil
}
