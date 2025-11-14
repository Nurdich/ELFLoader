//go:build linux && amd64
// +build linux,amd64

package coffer

/*
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Function pointer type for BOF entry point
typedef void (*bof_entry_t)(char* args, int argsSize);

// Resolve symbol from system libraries
void* resolveSymbol(const char* symbolName) {
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (handle == NULL) {
        return NULL;
    }
    
    void* addr = dlsym(handle, symbolName);
    return addr;
}

// Call BOF entry point function
void callBofEntryFunc(void* entryAddr, char* args, int argsSize) {
    bof_entry_t entryFunc = (bof_entry_t)entryAddr;
    if (entryFunc != NULL) {
        entryFunc(args, argsSize);
    }
}
*/
import "C"
import (
	"reflect"
	"strings"
	"unsafe"
)

// Function pointer storage for Beacon API functions
// This map stores Go function pointers that need to be callable from C
var beaconFunctionPointers = make(map[string]uintptr)

// getFunctionPointer converts a Go function to a C function pointer
// On Linux, we use reflect to get the function address
// Note: Go function pointers are not directly callable from C code.
// For proper integration, we would need CGO callbacks or assembly trampolines.
// This implementation gets the function pointer, but the actual calling
// mechanism depends on how the BOF code expects to call these functions.
func getFunctionPointer(fn interface{}) uintptr {
	if fn == nil {
		return 0
	}

	// Use reflect to get the function value
	fnValue := reflect.ValueOf(fn)
	if fnValue.Kind() != reflect.Func {
		return 0
	}

	// Get the function pointer
	// This returns the address of the Go function code
	fnPtr := fnValue.Pointer()
	return fnPtr
}

// resolveSystemSymbol resolves symbols from system libraries using dlopen/dlsym
// Supports libc$ prefix used by nix_bof_template (e.g., libc$getuid -> getuid)
func resolveSystemSymbol(symbolName string) uintptr {
	if symbolName == "" {
		return 0
	}

	// Handle libc$ prefix used by nix_bof_template
	// Example: libc$getuid -> getuid
	actualSymbolName := symbolName
	if strings.HasPrefix(symbolName, "libc$") {
		actualSymbolName = symbolName[5:] // Remove "libc$" prefix
	}

	cname := C.CString(actualSymbolName)
	defer C.free(unsafe.Pointer(cname))

	addr := C.resolveSymbol(cname)
	if addr == nil {
		return 0
	}

	return uintptr(unsafe.Pointer(addr))
}

// callBofEntry calls the BOF entry point function using C wrapper
func callBofEntry(entryAddr uintptr, argsPtr uintptr, argsSize uintptr) {
	if entryAddr == 0 {
		return
	}

	// Use C wrapper to call the function
	// This ensures proper calling convention (System V AMD64 ABI)
	C.callBofEntryFunc(
		unsafe.Pointer(entryAddr),
		(*C.char)(unsafe.Pointer(argsPtr)),
		C.int(argsSize),
	)
}

