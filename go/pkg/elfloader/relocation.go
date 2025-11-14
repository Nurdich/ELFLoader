package elfloader

import (
	"debug/elf"
	"fmt"
	"runtime"
)

// Relocation types for x86
const (
	R_386_32   = 1
	R_386_PC32 = 2
)

// Relocation types for x86_64
const (
	R_X86_64_64           = 1
	R_X86_64_PC32         = 2
	R_X86_64_GOT32        = 3
	R_X86_64_PLT32        = 4
	R_X86_64_GOTPCREL     = 9
	R_X86_64_32           = 10
	R_X86_64_32S          = 11
	R_X86_64_PC64         = 24
	R_X86_64_GOTPCRELX    = 41
	R_X86_64_REX_GOTPCRELX = 42
)

// processRelocations processes all relocation sections
func processRelocations(info *ELFInfo) error {
	for i, section := range info.Sections {
		// Process relocation sections
		if section.Type == elf.SHT_REL || section.Type == elf.SHT_RELA {
			if err := processRelocationSection(info, i, section); err != nil {
				return err
			}
		}
	}
	return nil
}

// processRelocationSection processes a single relocation section
func processRelocationSection(info *ELFInfo, sectionIndex int, section *elf.Section) error {
	// Get the section this relocation applies to
	targetSectionIndex := int(section.Info)
	if targetSectionIndex >= len(info.SectionMappings) {
		return fmt.Errorf("relocation target section index out of range")
	}

	targetAddr := info.SectionMappings[targetSectionIndex]
	if targetAddr == 0 {
		// Section not loaded, skip relocations
		return nil
	}

	// Read relocation data
	data, err := section.Data()
	if err != nil {
		return fmt.Errorf("failed to read relocation section data: %v", err)
	}

	// Process relocations based on type
	if section.Type == elf.SHT_RELA {
		return processRelaRelocations(info, data, targetSectionIndex, targetAddr)
	}
	return processRelRelocations(info, data, targetSectionIndex, targetAddr)
}

// processRelaRelocations processes RELA type relocations (with addend)
func processRelaRelocations(info *ELFInfo, data []byte, targetSectionIndex int, targetAddr uintptr) error {
	switch runtime.GOARCH {
	case "amd64":
		return processRela64(info, data, targetSectionIndex, targetAddr)
	case "386":
		return processRela32(info, data, targetSectionIndex, targetAddr)
	default:
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
}

// processRelRelocations processes REL type relocations (without addend)
func processRelRelocations(info *ELFInfo, data []byte, targetSectionIndex int, targetAddr uintptr) error {
	switch runtime.GOARCH {
	case "386":
		return processRel32(info, data, targetSectionIndex, targetAddr)
	default:
		return fmt.Errorf("REL relocations not supported for architecture: %s", runtime.GOARCH)
	}
}

// processRela64 processes 64-bit RELA relocations
func processRela64(info *ELFInfo, data []byte, targetSectionIndex int, targetAddr uintptr) error {
	entrySize := 24 // sizeof(Elf64_Rela)
	numEntries := len(data) / entrySize

	for i := 0; i < numEntries; i++ {
		offset := i * entrySize

		// Parse Rela entry
		rOffset := readUint64(data[offset:])
		rInfo := readUint64(data[offset+8:])
		rAddend := readInt64(data[offset+16:])

		symIndex := rInfo >> 32
		relType := rInfo & 0xffffffff

		// Get symbol
		if int(symIndex) >= len(info.SymbolTable) {
			continue
		}
		sym := info.SymbolTable[symIndex]

		// Apply relocation
		relocAddr := targetAddr + uintptr(rOffset)

		// Check if symbol is undefined (external symbol)
		if sym.Section == elf.SHN_UNDEF {
			// Handle special linker symbols (don't create thunks for these)
			if sym.Name == "_GLOBAL_OFFSET_TABLE_" || sym.Name == "_DYNAMIC" {
				// For object files, these symbols can be ignored or set to 0
				// Skip this relocation
				continue
			}

			// External symbol - resolve it
			symAddr, err := lookupExternalSymbol(sym.Name)
			if err != nil {
				return fmt.Errorf("failed to resolve external symbol %s: %v", sym.Name, err)
			}

			// Handle based on relocation type
			switch relType {
			case R_X86_64_PLT32:
				// Function call - create thunk trampoline
				thunkAddr, err := createThunkTrampoline(info, symAddr)
				if err != nil {
					return fmt.Errorf("failed to create thunk for %s: %v", sym.Name, err)
				}
				value := int32(int64(thunkAddr) - int64(relocAddr) + rAddend)
				writeInt32At(relocAddr, 0, value)

			case R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX:
				// GOT-relative - for object files, resolve directly
				// These are often used for global variables
				value := int32(int64(symAddr) + rAddend - int64(relocAddr))
				writeInt32At(relocAddr, 0, value)

			case R_X86_64_PC32:
				// PC-relative 32-bit - can be function or data
				// Create thunk for safety
				thunkAddr, err := createThunkTrampoline(info, symAddr)
				if err != nil {
					return fmt.Errorf("failed to create thunk for %s: %v", sym.Name, err)
				}
				value := int32(int64(thunkAddr) - int64(relocAddr) + rAddend)
				writeInt32At(relocAddr, 0, value)

			case R_X86_64_64:
				// Direct 64-bit address
				value := uint64(symAddr) + uint64(rAddend)
				writeUint64At(relocAddr, 0, value)

			case R_X86_64_32:
				// Direct 32-bit zero extended
				value := uint32(uint64(symAddr) + uint64(rAddend))
				writeUint32At(relocAddr, 0, value)

			case R_X86_64_32S:
				// Direct 32-bit sign extended
				value := int32(int64(symAddr) + rAddend)
				writeInt32At(relocAddr, 0, value)

			default:
				return fmt.Errorf("unsupported relocation type for external symbol: %d", relType)
			}
		} else {
			// Internal symbol - resolve normally
			symAddr := info.SectionMappings[sym.Section] + uintptr(sym.Value)

			switch relType {
			case R_X86_64_64:
				// Direct 64-bit
				value := uint64(symAddr) + uint64(rAddend)
				writeUint64At(relocAddr, 0, value)

			case R_X86_64_PC32, R_X86_64_PLT32:
				// PC-relative 32-bit
				value := int32(int64(symAddr) + rAddend - int64(relocAddr))
				writeInt32At(relocAddr, 0, value)

			case R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX:
				// GOT-relative PC-relative 32-bit
				// For object files without GOT, treat like PC-relative
				value := int32(int64(symAddr) + rAddend - int64(relocAddr))
				writeInt32At(relocAddr, 0, value)

			case R_X86_64_32:
				// Direct 32-bit zero extended
				value := uint32(uint64(symAddr) + uint64(rAddend))
				writeUint32At(relocAddr, 0, value)

			case R_X86_64_32S:
				// Direct 32-bit sign extended
				value := int32(int64(symAddr) + rAddend)
				writeInt32At(relocAddr, 0, value)

			default:
				return fmt.Errorf("unsupported relocation type: %d", relType)
			}
		}
	}
	return nil
}

// processRel32 processes 32-bit REL relocations
func processRel32(info *ELFInfo, data []byte, targetSectionIndex int, targetAddr uintptr) error {
	entrySize := 8 // sizeof(Elf32_Rel)
	numEntries := len(data) / entrySize

	for i := 0; i < numEntries; i++ {
		offset := i * entrySize

		// Parse Rel entry
		rOffset := readUint32(data[offset:])
		rInfo := readUint32(data[offset+4:])

		symIndex := rInfo >> 8
		relType := rInfo & 0xff

		// Get symbol
		if int(symIndex) >= len(info.SymbolTable) {
			continue
		}
		sym := info.SymbolTable[symIndex]

		// Resolve symbol address
		symAddr, err := resolveSymbol(info, &sym)
		if err != nil {
			return fmt.Errorf("failed to resolve symbol %s: %v", sym.Name, err)
		}

		// Apply relocation
		relocAddr := targetAddr + uintptr(rOffset)

		switch relType {
		case R_386_32:
			// Direct 32-bit
			addend := readInt32At(relocAddr, 0)
			value := int32(int64(symAddr) + int64(addend))
			writeInt32At(relocAddr, 0, value)

		case R_386_PC32:
			// PC-relative 32-bit
			addend := readInt32At(relocAddr, 0)
			value := int32(int64(symAddr) - int64(relocAddr) + int64(addend))
			writeInt32At(relocAddr, 0, value)

		default:
			return fmt.Errorf("unsupported relocation type: %d", relType)
		}
	}
	return nil
}

// processRela32 processes 32-bit RELA relocations
func processRela32(info *ELFInfo, data []byte, targetSectionIndex int, targetAddr uintptr) error {
	entrySize := 12 // sizeof(Elf32_Rela)
	numEntries := len(data) / entrySize

	for i := 0; i < numEntries; i++ {
		offset := i * entrySize

		// Parse Rela entry
		rOffset := readUint32(data[offset:])
		rInfo := readUint32(data[offset+4:])
		rAddend := readInt32(data[offset+8:])

		symIndex := rInfo >> 8
		relType := rInfo & 0xff

		// Get symbol
		if int(symIndex) >= len(info.SymbolTable) {
			continue
		}
		sym := info.SymbolTable[symIndex]

		// Resolve symbol address
		symAddr, err := resolveSymbol(info, &sym)
		if err != nil {
			return fmt.Errorf("failed to resolve symbol %s: %v", sym.Name, err)
		}

		// Apply relocation
		relocAddr := targetAddr + uintptr(rOffset)

		switch relType {
		case R_386_32:
			// Direct 32-bit
			value := int32(int64(symAddr) + int64(rAddend))
			writeInt32At(relocAddr, 0, value)

		case R_386_PC32:
			// PC-relative 32-bit
			value := int32(int64(symAddr) - int64(relocAddr) + int64(rAddend))
			writeInt32At(relocAddr, 0, value)

		default:
			return fmt.Errorf("unsupported relocation type: %d", relType)
		}
	}
	return nil
}

// Helper functions to read integers from byte slices
func readUint32(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}

func readUint64(data []byte) uint64 {
	return uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
		uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
}

func readInt32(data []byte) int64 {
	return int64(int32(readUint32(data)))
}

func readInt64(data []byte) int64 {
	return int64(readUint64(data))
}
