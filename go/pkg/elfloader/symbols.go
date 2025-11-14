package elfloader

import (
	"debug/elf"
	"fmt"
	"plugin"
	"runtime"
	"unsafe"

	"github.com/Nurdich/ELFLoader/pkg/beacon"
)

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
*/
import "C"

// InternalFunction represents an internal API function
type InternalFunction struct {
	Name string
	Ptr  uintptr
}

// GetInternalFunctions returns the list of internal Beacon API functions
func GetInternalFunctions() []InternalFunction {
	return []InternalFunction{
		{"BeaconDataParse", getFuncAddr(beacon.BeaconDataParse)},
		{"BeaconDataInt", getFuncAddr(beacon.BeaconDataInt)},
		{"BeaconDataShort", getFuncAddr(beacon.BeaconDataShort)},
		{"BeaconDataLength", getFuncAddr(beacon.BeaconDataLength)},
		{"BeaconDataExtract", getFuncAddr(beacon.BeaconDataExtract)},
		{"BeaconFormatAlloc", getFuncAddr(beacon.BeaconFormatAlloc)},
		{"BeaconFormatReset", getFuncAddr(beacon.BeaconFormatReset)},
		{"BeaconFormatFree", getFuncAddr(beacon.BeaconFormatFree)},
		{"BeaconFormatAppend", getFuncAddr(beacon.BeaconFormatAppend)},
		{"BeaconFormatPrintf", getFuncAddr(beacon.BeaconFormatPrintf)},
		{"BeaconFormatToString", getFuncAddr(beacon.BeaconFormatToString)},
		{"BeaconFormatInt", getFuncAddr(beacon.BeaconFormatInt)},
		{"BeaconPrintf", getFuncAddr(beacon.BeaconPrintf)},
		{"BeaconOutput", getFuncAddr(beacon.BeaconOutput)},
		{"BeaconIsAdmin", getFuncAddr(beacon.BeaconIsAdmin)},
		{"getEnviron", getFuncAddr(beacon.GetEnviron)},
		{"getOSName", getFuncAddr(beacon.GetOSName)},
	}
}

// resolveSymbol resolves a symbol to its address
func resolveSymbol(info *ELFInfo, sym *elf.Symbol) (uintptr, error) {
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

// Helper function to get the address of a Go function
// Note: This is a simplified version and may not work for all function types
func getFuncAddr(fn interface{}) uintptr {
	// This is a placeholder - getting function addresses in Go is tricky
	// For actual implementation, we would need to export these via CGO
	return 0
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
