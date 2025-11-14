// Wrapper to include ELFLoader.c with minimal beacon compatibility
// This prevents conflicts with CGO-exported Beacon API functions

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifndef WIN32
#include <sys/mman.h>
#include <dlfcn.h>
#else
#include <windows.h>
#endif

#include "debug.h"
#include "minimal_elf.h"
#include "ELFLoader.h"

// Use our minimal compatibility header instead of beacon_compatibility.h
#include "beacon_compat_minimal.h"

// Now include the ELFLoader.c implementation, but skip its includes
#define STDIO_H
#define STDLIB_H
#define STDINT_H
#define STRING_H
#define SYS_MMAN_H
#define DLFCN_H
#define DEBUG_H
#define MINIMAL_ELF_H
#define ELFLOADER_H
#define BEACON_COMPATIBILITY_H_  // This prevents including beacon_compatibility.h

// Read the ELFLoader.c source, skipping the already-included headers
// We need to manually include just the implementation code
