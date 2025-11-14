package elfloader

import (
	"debug/elf"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	// Thunk trampoline sizes
	ThunkTrampolineSize64 = 12
	ThunkTrampolineSize32 = 8

	// Memory protection flags (Unix)
	PROT_READ  = 0x1
	PROT_WRITE = 0x2
	PROT_EXEC  = 0x4

	// Map flags
	MAP_PRIVATE   = 0x2
	MAP_ANONYMOUS = 0x20
)

// ELFInfo holds information about the loaded ELF file
type ELFInfo struct {
	Header              *elf.FileHeader
	Sections            []*elf.Section
	SectionMappings     []uintptr
	SectionProts        []int
	SymbolTable         []elf.Symbol
	StringTable         []byte
	SectionStringTable  []byte
	TempOffsetTable     uintptr
	TempOffsetCounter   int
	RawData             []byte
	File                *elf.File
}

// ThunkTrampoline templates for different architectures
var (
	// x86_64: movabs rax, 0xEEEEEEEEEEEEEEEE; jmp rax
	ThunkTrampoline64 = []byte{0x48, 0xb8, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xff, 0xe0}
	ThunkOffset64     = 2

	// x86: push 0x00000000; pop eax; jmp eax
	ThunkTrampoline32 = []byte{0x68, 0x00, 0x00, 0x00, 0x00, 0x58, 0xff, 0xe0}
	ThunkOffset32     = 1
)

// Unhexlify converts a hex string to bytes
func Unhexlify(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}

	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		_, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		result[i/2] = b
	}
	return result, nil
}

// ELFRunner loads and executes an ELF object file
func ELFRunner(functionName string, elfObjectData []byte, argumentData []byte) error {
	// Verify ELF magic bytes
	if len(elfObjectData) < 4 || elfObjectData[0] != 0x7f ||
		elfObjectData[1] != 'E' || elfObjectData[2] != 'L' || elfObjectData[3] != 'F' {
		return fmt.Errorf("not an ELF file")
	}

	// Parse ELF file
	elfFile, err := elf.NewFile(newBytesReader(elfObjectData))
	if err != nil {
		return fmt.Errorf("failed to parse ELF file: %v", err)
	}
	defer elfFile.Close()

	// Verify it's a relocatable object file
	if elfFile.Type != elf.ET_REL {
		return fmt.Errorf("ELF type is not relocatable")
	}

	// Verify machine architecture
	expectedMachine := getExpectedMachine()
	if elfFile.Machine != expectedMachine {
		return fmt.Errorf("ELF machine type mismatch: got %v, expected %v", elfFile.Machine, expectedMachine)
	}

	info := &ELFInfo{
		Header:            &elfFile.FileHeader,
		Sections:          elfFile.Sections,
		SectionMappings:   make([]uintptr, len(elfFile.Sections)),
		SectionProts:      make([]int, len(elfFile.Sections)),
		RawData:           elfObjectData,
		File:              elfFile,
	}

	// Allocate thunk trampoline table
	thunkSize := 255 * getThunkTrampolineSize()
	thunkAddr, err := mmap(0, uintptr(thunkSize), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, ^uintptr(0), 0)
	if err != nil {
		return fmt.Errorf("failed to allocate thunk table: %v", err)
	}
	defer munmap(thunkAddr, thunkSize)
	info.TempOffsetTable = thunkAddr

	// Load sections
	if err := loadSections(info); err != nil {
		cleanupSections(info)
		return err
	}
	defer cleanupSections(info)

	// Load symbol table
	if err := loadSymbols(info); err != nil {
		return err
	}

	// Process relocations
	if err := processRelocations(info); err != nil {
		return err
	}

	// Set memory protections
	if err := setMemoryProtections(info); err != nil {
		return err
	}

	// Find and call the function
	funcPtr, err := findFunction(info, functionName)
	if err != nil {
		return err
	}

	// Execute the function (implemented in executor.go with CGO)
	executeFunction(funcPtr, argumentData, len(argumentData))

	return nil
}

// getExpectedMachine returns the expected ELF machine type for the current architecture
func getExpectedMachine() elf.Machine {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64
	case "386":
		return elf.EM_386
	default:
		return elf.EM_NONE
	}
}

// getThunkTrampolineSize returns the thunk trampoline size for the current architecture
func getThunkTrampolineSize() int {
	switch runtime.GOARCH {
	case "amd64":
		return ThunkTrampolineSize64
	case "386":
		return ThunkTrampolineSize32
	default:
		return 0
	}
}

// loadSections loads ELF sections into memory
func loadSections(info *ELFInfo) error {
	for i, section := range info.Sections {
		// Determine section protections
		prot := PROT_READ | PROT_WRITE
		if section.Flags&elf.SHF_WRITE != 0 {
			prot = PROT_READ | PROT_WRITE
		}
		if section.Flags&elf.SHF_EXECINSTR != 0 {
			prot = PROT_READ | PROT_EXEC
		}
		info.SectionProts[i] = prot

		// Allocate memory for PROGBITS sections
		if section.Size > 0 && section.Type == elf.SHT_PROGBITS {
			addr, err := mmap(0, uintptr(section.Size), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, ^uintptr(0), 0)
			if err != nil {
				return fmt.Errorf("failed to allocate memory for section %d: %v", i, err)
			}
			info.SectionMappings[i] = addr

			// Copy section data
			sectionData, err := section.Data()
			if err != nil {
				return fmt.Errorf("failed to read section %d data: %v", i, err)
			}
			copyToAddr(addr, sectionData)
		}

		// Track string tables and symbol tables
		switch section.Type {
		case elf.SHT_SYMTAB:
			// Symbol table will be loaded separately
		case elf.SHT_STRTAB:
			if section.Name == ".strtab" {
				data, _ := section.Data()
				info.StringTable = data
			} else if section.Name == ".shstrtab" {
				data, _ := section.Data()
				info.SectionStringTable = data
			}
		}
	}
	return nil
}

// loadSymbols loads the symbol table
func loadSymbols(info *ELFInfo) error {
	symbols, err := info.File.Symbols()
	if err != nil {
		// Try dynamic symbols if regular symbols fail
		symbols, err = info.File.DynamicSymbols()
		if err != nil {
			return fmt.Errorf("failed to load symbols: %v", err)
		}
	}
	info.SymbolTable = symbols
	return nil
}

// findFunction finds a function by name in the symbol table
func findFunction(info *ELFInfo, functionName string) (uintptr, error) {
	for _, sym := range info.SymbolTable {
		if sym.Name == functionName {
			if int(sym.Section) >= len(info.SectionMappings) {
				return 0, fmt.Errorf("symbol section index out of range")
			}
			baseAddr := info.SectionMappings[sym.Section]
			return baseAddr + uintptr(sym.Value), nil
		}
	}
	return 0, fmt.Errorf("function '%s' not found", functionName)
}

// setMemoryProtections sets the final memory protections for all sections
func setMemoryProtections(info *ELFInfo) error {
	// Protect thunk table
	thunkSize := 255 * getThunkTrampolineSize()
	if err := mprotect(info.TempOffsetTable, thunkSize, PROT_READ|PROT_EXEC); err != nil {
		return fmt.Errorf("failed to protect thunk table: %v", err)
	}

	// Protect sections
	for i, section := range info.Sections {
		if info.SectionMappings[i] != 0 {
			if err := mprotect(info.SectionMappings[i], int(section.Size), info.SectionProts[i]); err != nil {
				return fmt.Errorf("failed to protect section %d: %v", i, err)
			}
		}
	}
	return nil
}

// cleanupSections frees all allocated section memory
func cleanupSections(info *ELFInfo) {
	for i, addr := range info.SectionMappings {
		if addr != 0 && i < len(info.Sections) {
			munmap(addr, int(info.Sections[i].Size))
		}
	}
}

// Helper functions for memory operations

func copyToAddr(addr uintptr, data []byte) {
	slice := (*[1 << 30]byte)(unsafe.Pointer(addr))[:len(data):len(data)]
	copy(slice, data)
}

func writeInt32At(addr uintptr, offset int, value int32) {
	ptr := (*int32)(unsafe.Pointer(addr + uintptr(offset)))
	*ptr = value
}

func readInt32At(addr uintptr, offset int) int32 {
	ptr := (*int32)(unsafe.Pointer(addr + uintptr(offset)))
	return *ptr
}

func writeUint64At(addr uintptr, offset int, value uint64) {
	ptr := (*uint64)(unsafe.Pointer(addr + uintptr(offset)))
	*ptr = value
}

func writeUint32At(addr uintptr, offset int, value uint32) {
	ptr := (*uint32)(unsafe.Pointer(addr + uintptr(offset)))
	*ptr = value
}

// getString extracts a null-terminated string from a byte slice at the given offset
func getString(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

// Memory management syscalls - platform specific wrappers

func mmap(addr, length, prot, flags, fd, offset uintptr) (uintptr, error) {
	ret, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		addr,
		length,
		prot,
		flags,
		fd,
		offset,
	)
	if errno != 0 {
		return 0, errno
	}
	return ret, nil
}

func munmap(addr uintptr, length int) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_MUNMAP,
		addr,
		uintptr(length),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func mprotect(addr uintptr, length, prot int) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_MPROTECT,
		addr,
		uintptr(length),
		uintptr(prot),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// Helper to create a bytes.Reader-like interface for elf.NewFile
type bytesReaderAt struct {
	data []byte
}

func newBytesReader(data []byte) *bytesReaderAt {
	return &bytesReaderAt{data: data}
}

func (r *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off > int64(len(r.data)) {
		return 0, fmt.Errorf("invalid offset")
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		err = fmt.Errorf("EOF")
	}
	return
}
