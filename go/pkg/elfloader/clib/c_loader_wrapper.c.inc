// c_loader_wrapper.c
// Wrapper to call the C ELFLoader implementation from Go

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Forward declaration - actual implementation is in ELFLoader.c
extern int ELFRunner(char* functionName, unsigned char* elfObjectData, unsigned int size, unsigned char* argumentdata, int argumentSize);

// Wrapper function that can be called from Go
int call_c_elfloader(char* functionName, unsigned char* elfObjectData, unsigned int size, unsigned char* argumentdata, int argumentSize) {
    return ELFRunner(functionName, elfObjectData, size, argumentdata, argumentSize);
}
