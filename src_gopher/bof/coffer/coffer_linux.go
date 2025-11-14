//go:build linux && amd64

package coffer

import (
	"bytes"
	"debug/elf"
	"fmt"
	"gopher/utils"
	"runtime/debug"
	"syscall"
	"unsafe"
)

// X86_64 ELF relocation types
const (
	R_X86_64_NONE     = 0  // No relocation
	R_X86_64_64       = 1  // Direct 64 bit
	R_X86_64_PC32     = 2  // PC relative 32 bit signed
	R_X86_64_GOT32    = 3  // 32 bit GOT entry
	R_X86_64_PLT32    = 4  // 32 bit PLT address
	R_X86_64_COPY     = 5  // Copy symbol at runtime
	R_X86_64_GLOB_DAT = 6  // Create GOT entry
	R_X86_64_JUMP_SLOT = 7 // Create PLT entry
	R_X86_64_RELATIVE = 8  // Adjust by program base
	R_X86_64_GOTPCREL = 9  // 32 bit signed PC relative offset to GOT
)

type ElfSection struct {
	Section *elf.Section
	Address uintptr
	Size    uint64
}

type LoadedElf struct {
	File            *elf.File
	Sections        map[string]ElfSection
	GOT             map[string]uintptr // Global Offset Table
	BaseAddr        uintptr            // Base address for RELATIVE relocations
	TrampolineTable uintptr            // Trampoline table for external function calls
	TrampolineCount int                // Number of trampolines allocated
}

// X86_64 trampoline: mov rax, addr; jmp rax
// Bytes: 48 b8 [8-byte address] ff e0
var x86_64Trampoline = []byte{0x48, 0xb8, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xff, 0xe0}
var trampolineSize = 12 // Size of X86_64 trampoline
var trampolineOffset = 2 // Offset where address is written

// resolveExternalAddress resolves external symbols, especially Beacon API functions
func resolveExternalAddress(symbolName string, outChannel chan<- interface{}) uintptr {
	// First check internal Beacon API functions with CGO function pointers
	for _, fn := range GetInternalFunctions() {
		if fn.Name == symbolName {
			return fn.Ptr
		}
	}

	// Try to resolve from system libraries using dlopen/dlsym
	return resolveSystemSymbol(symbolName)
}

// mmapAllocate allocates executable memory using mmap
func mmapAllocate(size uintptr) (uintptr, error) {
	// Allocate memory with read, write, and execute permissions
	addr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,                                    // addr (let kernel choose)
		size,                                 // length
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC, // prot
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS, // flags
		^uintptr(0),                          // fd (-1)
		0,                                    // offset
	)

	if errno != 0 {
		return 0, fmt.Errorf("mmap failed: %v", errno)
	}

	return addr, nil
}

// mprotect changes memory protection
func mprotect(addr uintptr, size uintptr, prot int) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_MPROTECT,
		addr,
		size,
		uintptr(prot),
	)

	if errno != 0 {
		return fmt.Errorf("mprotect failed: %v", errno)
	}

	return nil
}

// processRelocation processes ELF relocations for X86_64
func processRelocation(relocAddr uintptr, symbolAddr uintptr, relocType uint32, addend int64, baseAddr uintptr) error {
	switch relocType {
	case R_X86_64_64:
		// Direct 64-bit absolute address
		*(*uint64)(unsafe.Pointer(relocAddr)) = uint64(symbolAddr) + uint64(addend)

	case R_X86_64_PC32:
		// 32-bit PC-relative offset
		offset := int64(symbolAddr) - int64(relocAddr+4) + addend
		if offset < -0x80000000 || offset > 0x7FFFFFFF {
			return fmt.Errorf("PC32 relocation out of range: %d", offset)
		}
		*(*int32)(unsafe.Pointer(relocAddr)) = int32(offset)

	case R_X86_64_PLT32:
		// 32-bit PLT-relative offset (similar to PC32 but through PLT)
		offset := int64(symbolAddr) - int64(relocAddr+4) + addend
		if offset < -0x80000000 || offset > 0x7FFFFFFF {
			return fmt.Errorf("PLT32 relocation out of range: %d", offset)
		}
		*(*int32)(unsafe.Pointer(relocAddr)) = int32(offset)

	case R_X86_64_RELATIVE:
		// Adjust by program base (used for shared libraries)
		// RELATIVE relocations: S + A where S is the base address
		// The addend contains the offset, we add the actual load base address
		*(*uint64)(unsafe.Pointer(relocAddr)) = uint64(baseAddr) + uint64(addend)

	case R_X86_64_GOTPCREL:
		// 32-bit signed PC-relative offset to GOT entry
		// GOT entry address - (relocation address + 4) + addend
		// The symbolAddr should already point to the GOT entry
		offset := int64(symbolAddr) - int64(relocAddr+4) + addend
		if offset < -0x80000000 || offset > 0x7FFFFFFF {
			return fmt.Errorf("GOTPCREL relocation out of range: %d", offset)
		}
		*(*int32)(unsafe.Pointer(relocAddr)) = int32(offset)

	case R_X86_64_GLOB_DAT:
		// Write absolute address to GOT entry
		*(*uint64)(unsafe.Pointer(relocAddr)) = uint64(symbolAddr) + uint64(addend)

	case R_X86_64_JUMP_SLOT:
		// Write absolute address to PLT GOT entry
		*(*uint64)(unsafe.Pointer(relocAddr)) = uint64(symbolAddr) + uint64(addend)

	default:
		return fmt.Errorf("unsupported relocation type: %d", relocType)
	}

	return nil
}

// Load loads an ELF file and executes the entry point (Linux version)
func Load(elfBytes []byte, argBytes []byte) ([]utils.BofMsg, error) {
	return LoadWithMethod(elfBytes, argBytes, "go")
}

// LoadWithMethod loads an ELF file and executes the specified method
func LoadWithMethod(elfBytes []byte, argBytes []byte, method string) ([]utils.BofMsg, error) {
	output := make(chan interface{})

	// Parse ELF file
	elfFile, err := elf.NewFile(bytes.NewReader(elfBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF file: %v", err)
	}
	defer elfFile.Close()

	// Verify architecture
	if elfFile.Machine != elf.EM_X86_64 {
		return nil, fmt.Errorf("unsupported architecture: %v (only X86_64 supported)", elfFile.Machine)
	}

	loadedElf := &LoadedElf{
		File:            elfFile,
		Sections:        make(map[string]ElfSection),
		GOT:             make(map[string]uintptr),
		TrampolineCount: 0,
	}

	// Verify ELF file type - should be ET_REL (relocatable object file)
	// This matches ELFLoader-main's requirement
	if elfFile.Type != elf.ET_REL {
		return nil, fmt.Errorf("unsupported ELF file type: %v (only ET_REL relocatable objects supported)", elfFile.Type)
	}

	// Allocate trampoline table for external function calls
	// Similar to ELFLoader-main's tempOffsetTable
	trampolineTableSize := uintptr(255 * trampolineSize) // Support up to 255 external functions
	trampolineTable, err := mmapAllocate(trampolineTableSize)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate trampoline table: %v", err)
	}
	loadedElf.TrampolineTable = trampolineTable

	// Set trampoline table to executable
	if err := mprotect(trampolineTable, trampolineTableSize, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		return nil, fmt.Errorf("failed to set trampoline table executable: %v", err)
	}

	// Find base address (first LOAD segment)
	var baseAddr uintptr = 0
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_LOAD {
			baseAddr = uintptr(prog.Vaddr)
			loadedElf.BaseAddr = baseAddr
			break
		}
	}

	// First pass: allocate memory for all sections that need to be loaded
	// This includes .got and .got.plt sections which are needed for relocations
	for _, section := range elfFile.Sections {
		if section.Size == 0 {
			continue
		}

		// Skip sections that don't need to be loaded into memory
		// But include .got, .got.plt, .bss sections
		if section.Type == elf.SHT_NOBITS && section.Name != ".bss" {
			continue
		}

		// Skip relocation sections (they are processed, not loaded)
		if section.Type == elf.SHT_RELA || section.Type == elf.SHT_REL {
			continue
		}

		// Allocate memory for section
		size := uintptr(section.Size)
		if section.Type == elf.SHT_NOBITS {
			// .bss section - allocate zero-filled memory
			size = uintptr(section.Size)
		}

		addr, err := mmapAllocate(size)
		if err != nil {
			return nil, fmt.Errorf("failed to allocate memory for section %s: %v", section.Name, err)
		}

		// Copy section data
		if section.Type != elf.SHT_NOBITS {
			data, err := section.Data()
			if err != nil {
				return nil, fmt.Errorf("failed to read section %s data: %v", section.Name, err)
			}
			copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(data)], data)
		} else {
			// Zero out .bss section
			for i := uintptr(0); i < size; i++ {
				*(*byte)(unsafe.Pointer(addr + i)) = 0
			}
		}

		// Set memory protection based on section flags
		prot := syscall.PROT_READ
		if section.Flags&elf.SHF_WRITE != 0 {
			prot |= syscall.PROT_WRITE
		}
		if section.Flags&elf.SHF_EXECINSTR != 0 {
			prot |= syscall.PROT_EXEC
		}

		if err := mprotect(addr, size, prot); err != nil {
			return nil, fmt.Errorf("failed to set memory protection for section %s: %v", section.Name, err)
		}

		loadedElf.Sections[section.Name] = ElfSection{
			Section: section,
			Address: addr,
			Size:    section.Size,
		}
	}

	// Process relocations
	if err := processRelocations(loadedElf, output); err != nil {
		return nil, fmt.Errorf("failed to process relocations: %v", err)
	}

	// Set the output channel for CGO exported Beacon API functions
	SetOutputChannel(output)
	defer ClearOutputChannel()

	// Call the entry point
	go invokeMethod(method, argBytes, loadedElf, output)

	// Collect output messages
	var msgs []utils.BofMsg
	bofMsg := utils.BofMsg{}

	for msg := range output {
		switch v := msg.(type) {
		case int:
			bofMsg.Type = v

		case []byte:
			bofMsg.Data = v
			msgs = append(msgs, bofMsg)
			bofMsg = utils.BofMsg{}

		case string:
			// Error message
			bofMsg.Type = 0x101 // BOF_ERROR
			bofMsg.Data = []byte(v)
			msgs = append(msgs, bofMsg)
			bofMsg = utils.BofMsg{}

		default:
			bofMsg = utils.BofMsg{}
		}
	}

	return msgs, nil
}

// processRelocations processes all relocations in the ELF file
func processRelocations(loadedElf *LoadedElf, output chan<- interface{}) error {
	// Get symbols first
	symbols, err := loadedElf.File.Symbols()
	if err != nil {
		// Try dynamic symbols if regular symbols fail
		symbols, err = loadedElf.File.DynamicSymbols()
		if err != nil {
			return fmt.Errorf("failed to read symbols: %v", err)
		}
	}

	// Process RELA sections (relocations with addend)
	for _, section := range loadedElf.File.Sections {
		if section.Type != elf.SHT_RELA {
			continue
		}

		// Parse RELA entries manually
		// Each RELA entry is 24 bytes: offset(8) + info(8) + addend(8)
		data, err := section.Data()
		if err != nil {
			continue
		}

		entrySize := 24 // Size of Elf64_Rela
		numEntries := len(data) / entrySize

		// Find the target section this relocation applies to
		// RELA sections have a link to the section they apply to
		targetSectionIndex := int(section.Link)
		if targetSectionIndex >= len(loadedElf.File.Sections) {
			continue
		}
		targetSection := loadedElf.File.Sections[targetSectionIndex]

		targetSectionInfo, exists := loadedElf.Sections[targetSection.Name]
		if !exists {
			continue
		}

		// Process each relocation entry
		for i := 0; i < numEntries; i++ {
			offset := i * entrySize
			if offset+entrySize > len(data) {
				break
			}

			// Parse Elf64_Rela structure
			relocOffset := uint64(data[offset]) | uint64(data[offset+1])<<8 | uint64(data[offset+2])<<16 | uint64(data[offset+3])<<24 |
				uint64(data[offset+4])<<32 | uint64(data[offset+5])<<40 | uint64(data[offset+6])<<48 | uint64(data[offset+7])<<56

			relocInfo := uint64(data[offset+8]) | uint64(data[offset+9])<<8 | uint64(data[offset+10])<<16 | uint64(data[offset+11])<<24 |
				uint64(data[offset+12])<<32 | uint64(data[offset+13])<<40 | uint64(data[offset+14])<<48 | uint64(data[offset+15])<<56

			relocAddend := int64(uint64(data[offset+16]) | uint64(data[offset+17])<<8 | uint64(data[offset+18])<<16 | uint64(data[offset+19])<<24 |
				uint64(data[offset+20])<<32 | uint64(data[offset+21])<<40 | uint64(data[offset+22])<<48 | uint64(data[offset+23])<<56)

			// Extract symbol index and type from info
			symIndex := int(relocInfo >> 32)
			relocType := uint32(relocInfo & 0xFFFFFFFF)

			if symIndex >= len(symbols) {
				continue
			}

			sym := symbols[symIndex]
			symbolName := sym.Name

			// Calculate relocation address
			relocAddr := targetSectionInfo.Address + uintptr(relocOffset-targetSection.Addr)
			symbolAddr := uintptr(0)

			// Resolve symbol address
			if sym.Section == elf.SHN_UNDEF {
				// External symbol - resolve from Beacon API or system libraries
				externalAddr := resolveExternalAddress(symbolName, output)
				if externalAddr == 0 {
					return fmt.Errorf("failed to resolve external symbol: %s", symbolName)
				}

				// For relocatable object files (ET_REL), external functions use trampoline mechanism
				// This matches ELFLoader-main's approach for PC32/PLT32 relocations
				if relocType == R_X86_64_PC32 || relocType == R_X86_64_PLT32 {
					// Create a trampoline: mov rax, addr; jmp rax
					if loadedElf.TrampolineCount >= 255 {
						return fmt.Errorf("too many external functions (max 255)")
					}
					trampolineAddr := loadedElf.TrampolineTable + uintptr(loadedElf.TrampolineCount*trampolineSize)

					// Copy trampoline template
					copy((*[12]byte)(unsafe.Pointer(trampolineAddr))[:], x86_64Trampoline)

					// Write the function address into the trampoline
					*(*uint64)(unsafe.Pointer(trampolineAddr + uintptr(trampolineOffset))) = uint64(externalAddr)

					// Calculate relative offset: trampolineAddr - (relocAddr + 4) + addend
					relativeOffset := int64(trampolineAddr) - int64(relocAddr+4) + relocAddend
					if relativeOffset < -0x80000000 || relativeOffset > 0x7FFFFFFF {
						return fmt.Errorf("trampoline offset out of range for %s: %d", symbolName, relativeOffset)
					}
					*(*int32)(unsafe.Pointer(relocAddr)) = int32(relativeOffset)
					loadedElf.TrampolineCount++
					continue // Skip normal relocation processing for trampoline
				}

				// For GOTPCREL, GLOB_DAT, and JUMP_SLOT, use GOT table
				if relocType == R_X86_64_GOTPCREL || relocType == R_X86_64_GLOB_DAT || relocType == R_X86_64_JUMP_SLOT {
					// Try to use actual .got or .got.plt section if it exists
					gotSectionName := ".got.plt"
					if relocType == R_X86_64_GOTPCREL {
						gotSectionName = ".got"
					}

					gotEntryAddr := uintptr(0)
					if gotSection, exists := loadedElf.Sections[gotSectionName]; exists {
						// Use the actual GOT section
						gotOffset := uintptr(len(loadedElf.GOT) * 8) // 8 bytes per entry
						if gotOffset+8 <= uintptr(gotSection.Size) {
							gotEntryAddr = gotSection.Address + gotOffset
							// Write the symbol address to GOT entry
							*(*uint64)(unsafe.Pointer(gotEntryAddr)) = uint64(externalAddr)
							loadedElf.GOT[symbolName] = gotEntryAddr
						} else {
							return fmt.Errorf("GOT section %s overflow for symbol %s", gotSectionName, symbolName)
						}
					} else {
						// Fallback: allocate memory for GOT entry if section doesn't exist
						if gotAddr, exists := loadedElf.GOT[symbolName]; exists {
							gotEntryAddr = gotAddr
						} else {
							gotMem, err := mmapAllocate(8)
							if err != nil {
								return fmt.Errorf("failed to allocate GOT entry for %s: %v", symbolName, err)
							}
							// Write the symbol address to GOT entry
							*(*uint64)(unsafe.Pointer(gotMem)) = uint64(externalAddr)
							loadedElf.GOT[symbolName] = gotMem
							gotEntryAddr = gotMem
						}
					}
					// Use GOT entry address for relocation
					symbolAddr = gotEntryAddr
				} else {
					// For other relocation types (like R_X86_64_64), use the address directly
					symbolAddr = externalAddr
				}
			} else {
				// Internal symbol - find its section
				if int(sym.Section) < len(loadedElf.File.Sections) {
					symSection := loadedElf.File.Sections[sym.Section]
					if symSectionInfo, exists := loadedElf.Sections[symSection.Name]; exists {
						symbolAddr = symSectionInfo.Address + uintptr(sym.Value)
					}
				}
			}

			// Apply relocation
			if err := processRelocation(relocAddr, symbolAddr, relocType, relocAddend, loadedElf.BaseAddr); err != nil {
				return fmt.Errorf("failed to process relocation for %s: %v", symbolName, err)
			}
		}
	}

	return nil
}

// invokeMethod invokes the entry point function
func invokeMethod(methodName string, argBytes []byte, loadedElf *LoadedElf, outChannel chan<- interface{}) {
	defer close(outChannel)

	// Catch panics
	defer func() {
		if r := recover(); r != nil {
			errorMsg := fmt.Sprintf("Panic occurred when executing ELF: %v\n%s", r, debug.Stack())
			outChannel <- errorMsg
		}
	}()

	// Find the entry symbol
	symbols, err := loadedElf.File.Symbols()
	if err != nil {
		outChannel <- fmt.Sprintf("Failed to read symbols: %v", err)
		return
	}

	var entryAddr uintptr = 0
	for _, sym := range symbols {
		if sym.Name == methodName {
			if sym.Section == elf.SHN_UNDEF {
				outChannel <- fmt.Sprintf("Entry symbol %s is undefined", methodName)
				return
			}

			symSection := loadedElf.File.Sections[sym.Section]
			if sectionInfo, exists := loadedElf.Sections[symSection.Name]; exists {
				entryAddr = sectionInfo.Address + uintptr(sym.Value)
				break
			}
		}
	}

	if entryAddr == 0 {
		outChannel <- fmt.Sprintf("Entry symbol %s not found", methodName)
		return
	}

	// Prepare arguments
	if len(argBytes) == 0 {
		argBytes = make([]byte, 1)
	}

	// Call the entry point using CGO wrapper
	// BOF entry function signature: void go(char* args, int argsSize)
	// X86_64 calling convention: RDI = args, RSI = argsSize
	argsPtr := uintptr(unsafe.Pointer(&argBytes[0]))
	argsSize := uintptr(len(argBytes))

	callBofEntry(entryAddr, argsPtr, argsSize)
}

