package elfloader

/*
#include <stdlib.h>
#include <stdint.h>

// Function pointer type for the loaded ELF function
typedef int (*elf_func_t)(unsigned char*, int);

// Execute a loaded ELF function via function pointer
static int execute_elf_function(uintptr_t func_ptr, unsigned char* args, int args_len) {
    if (func_ptr == 0) {
        return -1;
    }

    elf_func_t func = (elf_func_t)func_ptr;
    return func(args, args_len);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// executeFunction executes the loaded function using CGO
func executeFunction(funcPtr uintptr, args []byte, argsLen int) {
	fmt.Printf("Function loaded at address: 0x%x\n", funcPtr)
	fmt.Printf("Executing function with %d bytes of arguments...\n", argsLen)

	var argsPtr *C.uchar
	if len(args) > 0 {
		argsPtr = (*C.uchar)(unsafe.Pointer(&args[0]))
	}

	// Call the C wrapper to execute the function
	result := C.execute_elf_function(C.uintptr_t(funcPtr), argsPtr, C.int(argsLen))

	fmt.Printf("Function returned: %d\n", int(result))
}
