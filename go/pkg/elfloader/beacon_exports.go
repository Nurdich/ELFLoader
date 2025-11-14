package elfloader

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// We need variadic function wrappers for BeaconPrintf and BeaconFormatPrintf
// Since CGO doesn't support variadic exports directly, we'll use a workaround
*/
import "C"
import (
	"unsafe"

	"github.com/Nurdich/ELFLoader/pkg/beacon"
)

// CGO exports for Beacon API functions
// These functions are called from the loaded ELF object files

//export BeaconDataParse
func BeaconDataParse(parser unsafe.Pointer, buffer *C.uchar, size C.int) {
	if parser == nil {
		return
	}
	p := (*beacon.DataParser)(parser)
	buf := C.GoBytes(unsafe.Pointer(buffer), size)
	beacon.BeaconDataParse(p, buf, int(size))
}

//export BeaconDataInt
func BeaconDataInt(parser unsafe.Pointer) C.int {
	if parser == nil {
		return 0
	}
	p := (*beacon.DataParser)(parser)
	return C.int(beacon.BeaconDataInt(p))
}

//export BeaconDataShort
func BeaconDataShort(parser unsafe.Pointer) C.short {
	if parser == nil {
		return 0
	}
	p := (*beacon.DataParser)(parser)
	return C.short(beacon.BeaconDataShort(p))
}

//export BeaconDataLength
func BeaconDataLength(parser unsafe.Pointer) C.int {
	if parser == nil {
		return 0
	}
	p := (*beacon.DataParser)(parser)
	return C.int(beacon.BeaconDataLength(p))
}

//export BeaconDataExtract
func BeaconDataExtract(parser unsafe.Pointer, outsize *C.int) *C.uchar {
	if parser == nil {
		if outsize != nil {
			*outsize = 0
		}
		return nil
	}
	p := (*beacon.DataParser)(parser)
	data, size := beacon.BeaconDataExtract(p)
	if outsize != nil {
		*outsize = C.int(size)
	}
	if len(data) == 0 {
		return nil
	}
	// Allocate C memory for the result
	result := (*C.uchar)(C.malloc(C.size_t(size)))
	C.memcpy(unsafe.Pointer(result), unsafe.Pointer(&data[0]), C.size_t(size))
	return result
}

//export BeaconFormatAlloc
func BeaconFormatAlloc(format unsafe.Pointer, maxsz C.int) {
	if format == nil {
		return
	}
	f := (*beacon.FormatBuffer)(format)
	beacon.BeaconFormatAlloc(f, int(maxsz))
}

//export BeaconFormatReset
func BeaconFormatReset(format unsafe.Pointer) {
	if format == nil {
		return
	}
	f := (*beacon.FormatBuffer)(format)
	beacon.BeaconFormatReset(f)
}

//export BeaconFormatFree
func BeaconFormatFree(format unsafe.Pointer) {
	if format == nil {
		return
	}
	f := (*beacon.FormatBuffer)(format)
	beacon.BeaconFormatFree(f)
}

//export BeaconFormatAppend
func BeaconFormatAppend(format unsafe.Pointer, text *C.uchar, length C.int) {
	if format == nil {
		return
	}
	f := (*beacon.FormatBuffer)(format)
	data := C.GoBytes(unsafe.Pointer(text), length)
	beacon.BeaconFormatAppend(f, data)
}

//export BeaconFormatToString
func BeaconFormatToString(format unsafe.Pointer, outsize *C.int) *C.uchar {
	if format == nil {
		if outsize != nil {
			*outsize = 0
		}
		return nil
	}
	f := (*beacon.FormatBuffer)(format)
	data, size := beacon.BeaconFormatToString(f)
	if outsize != nil {
		*outsize = C.int(size)
	}
	if len(data) == 0 {
		return nil
	}
	// Allocate C memory for the result
	result := (*C.uchar)(C.malloc(C.size_t(size)))
	C.memcpy(unsafe.Pointer(result), unsafe.Pointer(&data[0]), C.size_t(size))
	return result
}

//export BeaconFormatInt
func BeaconFormatInt(format unsafe.Pointer, value C.int) {
	if format == nil {
		return
	}
	f := (*beacon.FormatBuffer)(format)
	beacon.BeaconFormatInt(f, int32(value))
}

//export BeaconOutput
func BeaconOutput(outputType C.int, data *C.uchar, length C.int) {
	buf := C.GoBytes(unsafe.Pointer(data), length)
	beacon.BeaconOutput(int(outputType), buf)
}

//export BeaconIsAdmin
func BeaconIsAdmin() C.int {
	return C.int(beacon.BeaconIsAdmin())
}

//export getEnviron
func getEnviron() **C.char {
	env := beacon.GetEnviron()
	if len(env) == 0 {
		return nil
	}

	// Allocate array of char* (NULL-terminated)
	result := (**C.char)(C.malloc(C.size_t(len(env)+1) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	ptrSlice := (*[1 << 30]*C.char)(unsafe.Pointer(result))[:len(env)+1:len(env)+1]

	for i, s := range env {
		ptrSlice[i] = C.CString(s)
	}
	ptrSlice[len(env)] = nil // NULL terminator

	return result
}

//export getOSName
func getOSName() *C.char {
	return C.CString(beacon.GetOSName())
}

// BeaconPrintf is handled specially since it's variadic
// We need a C wrapper to handle the variadic arguments

//export GoBeaconPrintf
func GoBeaconPrintf(outputType C.int, message *C.char) {
	msg := C.GoString(message)
	beacon.BeaconPrintf(int(outputType), "%s", msg)
}

//export GoBeaconFormatPrintf
func GoBeaconFormatPrintf(format unsafe.Pointer, message *C.char) {
	if format == nil {
		return
	}
	f := (*beacon.FormatBuffer)(format)
	msg := C.GoString(message)
	beacon.BeaconFormatPrintf(f, "%s", msg)
}
