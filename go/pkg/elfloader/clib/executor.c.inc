// executor.c - CGO wrapper for executing loaded ELF functions
#include <stdint.h>

// Function pointer type for the loaded ELF function
typedef int (*elf_func_t)(unsigned char*, int);

// Execute a loaded ELF function via function pointer
int execute_elf_function(uintptr_t func_ptr, unsigned char* args, int args_len) {
    if (func_ptr == 0) {
        return -1;
    }

    elf_func_t func = (elf_func_t)func_ptr;
    return func(args, args_len);
}
