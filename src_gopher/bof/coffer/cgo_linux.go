//go:build linux && amd64
// +build linux,amd64

package coffer

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

// Function pointer type for BOF entry point
typedef void (*bof_entry_t)(char* args, int argsSize);

// Resolve symbol from system libraries
static void* resolveSymbol(const char* symbolName) {
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (handle == NULL) {
        return NULL;
    }

    void* addr = dlsym(handle, symbolName);
    return addr;
}

// Call BOF entry point function
static void callBofEntryFunc(void* entryAddr, char* args, int argsSize) {
    bof_entry_t entryFunc = (bof_entry_t)entryAddr;
    if (entryFunc != NULL) {
        entryFunc(args, argsSize);
    }
}

// Forward declarations for Go CGO exports
extern int GoBeaconOutput(int type, void* data, int length);
extern int GoBeaconPrintfImpl(int type, void* data, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
                              uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                              uintptr_t arg7, uintptr_t arg8, uintptr_t arg9);
extern void GoBeaconDataParse(void* parser, void* buffer, int size);
extern int GoBeaconDataInt(void* parser);
extern short GoBeaconDataShort(void* parser);
extern int GoBeaconDataLength(void* parser);
extern void* GoBeaconDataExtract(void* parser, int* outsize);
extern void GoBeaconFormatAlloc(void* format, int maxsz);
extern void GoBeaconFormatReset(void* format);
extern void GoBeaconFormatFree(void* format);
extern void GoBeaconFormatAppend(void* format, void* text, int len);
extern int GoBeaconFormatToString(void* format, void* buffer, int maxsz);
extern void GoBeaconFormatInt(void* format, int value);
extern int GoBeaconFormatPrintfImpl(void* format, void* fmtPtr, uintptr_t arg0, uintptr_t arg1,
                                     uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5,
                                     uintptr_t arg6, uintptr_t arg7, uintptr_t arg8, uintptr_t arg9);
extern int GoBeaconAddValue(void* key, void* ptr);
extern void* GoBeaconGetValue(void* key);
extern int GoBeaconRemoveValue(void* key);

// Variadic wrapper for BeaconOutput (called from BOF code)
static int BeaconOutput_wrapper(int type, void* data, int length) {
    return GoBeaconOutput(type, data, length);
}

// Variadic wrapper for BeaconPrintf (called from BOF code)
static int BeaconPrintf_wrapper(int type, const char* fmt, ...) {
    // Capture up to 10 variadic arguments
    va_list args;
    va_start(args, fmt);

    uintptr_t arg0 = va_arg(args, uintptr_t);
    uintptr_t arg1 = va_arg(args, uintptr_t);
    uintptr_t arg2 = va_arg(args, uintptr_t);
    uintptr_t arg3 = va_arg(args, uintptr_t);
    uintptr_t arg4 = va_arg(args, uintptr_t);
    uintptr_t arg5 = va_arg(args, uintptr_t);
    uintptr_t arg6 = va_arg(args, uintptr_t);
    uintptr_t arg7 = va_arg(args, uintptr_t);
    uintptr_t arg8 = va_arg(args, uintptr_t);
    uintptr_t arg9 = va_arg(args, uintptr_t);

    va_end(args);

    return GoBeaconPrintfImpl(type, (void*)fmt, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
}

// Variadic wrapper for BeaconFormatPrintf (called from BOF code)
static int BeaconFormatPrintf_wrapper(void* format, const char* fmt, ...) {
    // Capture up to 10 variadic arguments
    va_list args;
    va_start(args, fmt);

    uintptr_t arg0 = va_arg(args, uintptr_t);
    uintptr_t arg1 = va_arg(args, uintptr_t);
    uintptr_t arg2 = va_arg(args, uintptr_t);
    uintptr_t arg3 = va_arg(args, uintptr_t);
    uintptr_t arg4 = va_arg(args, uintptr_t);
    uintptr_t arg5 = va_arg(args, uintptr_t);
    uintptr_t arg6 = va_arg(args, uintptr_t);
    uintptr_t arg7 = va_arg(args, uintptr_t);
    uintptr_t arg8 = va_arg(args, uintptr_t);
    uintptr_t arg9 = va_arg(args, uintptr_t);

    va_end(args);

    return GoBeaconFormatPrintfImpl(format, (void*)fmt, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
}

// Helper functions to get function pointers
static inline void* get_BeaconOutput_ptr() { return (void*)BeaconOutput_wrapper; }
static inline void* get_BeaconPrintf_ptr() { return (void*)BeaconPrintf_wrapper; }
static inline void* get_BeaconDataParse_ptr() { return (void*)GoBeaconDataParse; }
static inline void* get_BeaconDataInt_ptr() { return (void*)GoBeaconDataInt; }
static inline void* get_BeaconDataShort_ptr() { return (void*)GoBeaconDataShort; }
static inline void* get_BeaconDataLength_ptr() { return (void*)GoBeaconDataLength; }
static inline void* get_BeaconDataExtract_ptr() { return (void*)GoBeaconDataExtract; }
static inline void* get_BeaconFormatAlloc_ptr() { return (void*)GoBeaconFormatAlloc; }
static inline void* get_BeaconFormatReset_ptr() { return (void*)GoBeaconFormatReset; }
static inline void* get_BeaconFormatFree_ptr() { return (void*)GoBeaconFormatFree; }
static inline void* get_BeaconFormatAppend_ptr() { return (void*)GoBeaconFormatAppend; }
static inline void* get_BeaconFormatToString_ptr() { return (void*)GoBeaconFormatToString; }
static inline void* get_BeaconFormatInt_ptr() { return (void*)GoBeaconFormatInt; }
static inline void* get_BeaconFormatPrintf_ptr() { return (void*)BeaconFormatPrintf_wrapper; }
static inline void* get_BeaconAddValue_ptr() { return (void*)GoBeaconAddValue; }
static inline void* get_BeaconGetValue_ptr() { return (void*)GoBeaconGetValue; }
static inline void* get_BeaconRemoveValue_ptr() { return (void*)GoBeaconRemoveValue; }
*/
import "C"
import (
	"reflect"
	"strings"
	"unsafe"

	"gopher/bof/boffer"
)

// Global output channel for Beacon API functions
// This is set before executing BOF code and used by CGO exported functions
var currentOutputChannel chan<- interface{}

// Function pointer storage for Beacon API functions
// This map stores Go function pointers that need to be callable from C
var beaconFunctionPointers = make(map[string]uintptr)

// SetOutputChannel sets the current output channel for Beacon API calls
func SetOutputChannel(ch chan<- interface{}) {
	currentOutputChannel = ch
}

// ClearOutputChannel clears the current output channel
func ClearOutputChannel() {
	currentOutputChannel = nil
}

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

// InternalFunction represents an internal Beacon API function
type InternalFunction struct {
	Name string
	Ptr  uintptr
}

// GetInternalFunctions returns the list of internal Beacon API functions with CGO function pointers
func GetInternalFunctions() []InternalFunction {
	return []InternalFunction{
		{"BeaconOutput", uintptr(C.get_BeaconOutput_ptr())},
		{"BeaconPrintf", uintptr(C.get_BeaconPrintf_ptr())},
		{"BeaconDataParse", uintptr(C.get_BeaconDataParse_ptr())},
		{"BeaconDataInt", uintptr(C.get_BeaconDataInt_ptr())},
		{"BeaconDataShort", uintptr(C.get_BeaconDataShort_ptr())},
		{"BeaconDataLength", uintptr(C.get_BeaconDataLength_ptr())},
		{"BeaconDataExtract", uintptr(C.get_BeaconDataExtract_ptr())},
		{"BeaconFormatAlloc", uintptr(C.get_BeaconFormatAlloc_ptr())},
		{"BeaconFormatReset", uintptr(C.get_BeaconFormatReset_ptr())},
		{"BeaconFormatFree", uintptr(C.get_BeaconFormatFree_ptr())},
		{"BeaconFormatAppend", uintptr(C.get_BeaconFormatAppend_ptr())},
		{"BeaconFormatToString", uintptr(C.get_BeaconFormatToString_ptr())},
		{"BeaconFormatInt", uintptr(C.get_BeaconFormatInt_ptr())},
		{"BeaconFormatPrintf", uintptr(C.get_BeaconFormatPrintf_ptr())},
		{"BeaconAddValue", uintptr(C.get_BeaconAddValue_ptr())},
		{"BeaconGetValue", uintptr(C.get_BeaconGetValue_ptr())},
		{"BeaconRemoveValue", uintptr(C.get_BeaconRemoveValue_ptr())},
	}
}


// CGO Export functions - These are called from C code in BOF

//export GoBeaconOutput
func GoBeaconOutput(beaconType C.int, data unsafe.Pointer, length C.int) C.int {
	if currentOutputChannel == nil || length <= 0 {
		return 0
	}
	outputFunc := boffer.GetElfOutputForChannel(currentOutputChannel)
	return C.int(outputFunc(int(beaconType), uintptr(data), int(length)))
}

//export GoBeaconPrintfImpl
func GoBeaconPrintfImpl(beaconType C.int, fmtPtr unsafe.Pointer, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9 C.uintptr_t) C.int {
	if currentOutputChannel == nil {
		return 0
	}
	printfFunc := boffer.GetElfPrintfForChannel(currentOutputChannel)
	return C.int(printfFunc(int(beaconType), uintptr(fmtPtr), uintptr(arg0), uintptr(arg1), uintptr(arg2),
		uintptr(arg3), uintptr(arg4), uintptr(arg5), uintptr(arg6), uintptr(arg7), uintptr(arg8), uintptr(arg9)))
}

//export GoBeaconDataParse
func GoBeaconDataParse(parser unsafe.Pointer, buffer unsafe.Pointer, size C.int) {
	boffer.DataParse((*boffer.Datap)(parser), uintptr(buffer), uint32(size))
}

//export GoBeaconDataInt
func GoBeaconDataInt(parser unsafe.Pointer) C.int {
	return C.int(boffer.DataInt((*boffer.Datap)(parser)))
}

//export GoBeaconDataShort
func GoBeaconDataShort(parser unsafe.Pointer) C.short {
	return C.short(boffer.DataShort((*boffer.Datap)(parser)))
}

//export GoBeaconDataLength
func GoBeaconDataLength(parser unsafe.Pointer) C.int {
	return C.int(boffer.DataLength((*boffer.Datap)(parser)))
}

//export GoBeaconDataExtract
func GoBeaconDataExtract(parser unsafe.Pointer, outsize *C.int) unsafe.Pointer {
	size := uint32(0)
	result := boffer.DataExtract((*boffer.Datap)(parser), &size)
	if outsize != nil {
		*outsize = C.int(size)
	}
	return unsafe.Pointer(result)
}

//export GoBeaconFormatAlloc
func GoBeaconFormatAlloc(format unsafe.Pointer, maxsz C.int) {
	boffer.FormatAllocate((*boffer.Formatp)(format), uint32(maxsz))
}

//export GoBeaconFormatReset
func GoBeaconFormatReset(format unsafe.Pointer) {
	boffer.FormatReset((*boffer.Formatp)(format))
}

//export GoBeaconFormatFree
func GoBeaconFormatFree(format unsafe.Pointer) {
	boffer.FormatFree((*boffer.Formatp)(format))
}

//export GoBeaconFormatAppend
func GoBeaconFormatAppend(format unsafe.Pointer, text unsafe.Pointer, length C.int) {
	boffer.FormatAppend((*boffer.Formatp)(format), uintptr(text), uint32(length))
}

//export GoBeaconFormatToString
func GoBeaconFormatToString(format unsafe.Pointer, buffer unsafe.Pointer, maxsz C.int) C.int {
	return C.int(boffer.FormatToString((*boffer.Formatp)(format), uintptr(buffer), uint32(maxsz)))
}

//export GoBeaconFormatInt
func GoBeaconFormatInt(format unsafe.Pointer, value C.int) {
	boffer.FormatInt((*boffer.Formatp)(format), int32(value))
}

//export GoBeaconFormatPrintfImpl
func GoBeaconFormatPrintfImpl(format unsafe.Pointer, fmtPtr unsafe.Pointer, arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9 C.uintptr_t) C.int {
	boffer.FormatPrintfFunc((*boffer.Formatp)(format), uintptr(fmtPtr), uintptr(arg0), uintptr(arg1), uintptr(arg2),
		uintptr(arg3), uintptr(arg4), uintptr(arg5), uintptr(arg6), uintptr(arg7), uintptr(arg8), uintptr(arg9))
	return 0
}

//export GoBeaconAddValue
func GoBeaconAddValue(key unsafe.Pointer, ptr unsafe.Pointer) C.int {
	return C.int(boffer.AddValue(uintptr(key), uintptr(ptr)))
}

//export GoBeaconGetValue
func GoBeaconGetValue(key unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(boffer.GetValue(uintptr(key)))
}

//export GoBeaconRemoveValue
func GoBeaconRemoveValue(key unsafe.Pointer) C.int {
	return C.int(boffer.RemoveValue(uintptr(key)))
}
