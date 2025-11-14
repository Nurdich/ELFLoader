package elfloader

/*
#cgo CFLAGS: -I../../../includes -I../../../src -I./clib -DLIBRARY
#cgo LDFLAGS: -ldl

// Forward declaration of the C wrapper function
extern int call_c_elfloader(char* functionName, unsigned char* elfObjectData, unsigned int size, unsigned char* argumentdata, int argumentSize);

// Include the master C file that contains all the C sources
#include "clib/cgo_master.c"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ELFRunnerC uses the original C implementation to load and execute an ELF object file
func ELFRunnerC(functionName string, elfObjectData []byte, argumentData []byte) error {
	// Convert function name to C string
	cFunctionName := C.CString(functionName)
	defer C.free(unsafe.Pointer(cFunctionName))

	// Prepare ELF data pointer
	var elfPtr *C.uchar
	if len(elfObjectData) > 0 {
		elfPtr = (*C.uchar)(unsafe.Pointer(&elfObjectData[0]))
	}

	// Prepare argument data pointer
	var argPtr *C.uchar
	var argLen C.int
	if len(argumentData) > 0 {
		argPtr = (*C.uchar)(unsafe.Pointer(&argumentData[0]))
		argLen = C.int(len(argumentData))
	}

	// Call the C ELFRunner
	result := C.call_c_elfloader(
		cFunctionName,
		elfPtr,
		C.uint(len(elfObjectData)),
		argPtr,
		argLen,
	)

	if result != 0 {
		return fmt.Errorf("C ELFRunner failed with error code: %d", result)
	}

	return nil
}
