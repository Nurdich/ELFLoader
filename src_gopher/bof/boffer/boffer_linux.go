//go:build linux && amd64

package boffer

import (
	"fmt"
	"math"
	"strings"
	"syscall"
	"unsafe"

	"gopher/bof/memory"
)

type (
	// Datap represents a data parser for Beacon data
	Datap struct {
		Original uintptr
		Buffer   uintptr
		Length   uint32
		Size     uint32
	}

	// Formatp represents a format buffer for Beacon output
	Formatp struct {
		Original uintptr
		Buffer   uintptr
		Length   uint32
		Size     uint32
	}
)

func parsePrintfFormat(fmtStr string, args []uintptr) string {
	result := ""
	argOffset := 0
	i := 0

	for i < len(fmtStr) {
		if fmtStr[i] == '%' && i < len(fmtStr)-1 {
			i++ // ignore '%'

			// ignore flags (-, +, space, #, 0)
			for i < len(fmtStr) && strings.ContainsRune("-+ #0", rune(fmtStr[i])) {
				i++
			}

			// ignore length (numbers or *)
			if i < len(fmtStr) && fmtStr[i] == '*' {
				i++
				argOffset++ // * uses argument
			} else {
				for i < len(fmtStr) && fmtStr[i] >= '0' && fmtStr[i] <= '9' {
					i++
				}
			}

			// ignore accuracy (.numbers or .*)
			if i < len(fmtStr) && fmtStr[i] == '.' {
				i++
				if i < len(fmtStr) && fmtStr[i] == '*' {
					i++
					argOffset++
				} else {
					for i < len(fmtStr) && fmtStr[i] >= '0' && fmtStr[i] <= '9' {
						i++
					}
				}
			}

			// parse specifier
			if i >= len(fmtStr) {
				break
			}

			spec := fmtStr[i]
			if argOffset < len(args) {
				switch spec {
				case 'd', 'i', 'u', 'o', 'x', 'X':
					// Integer
					result += fmt.Sprintf("%"+string(spec), args[argOffset])
				case 'c':
					// Character
					result += string(rune(args[argOffset]))
				case 's':
					// String
					strPtr := args[argOffset]
					if strPtr != 0 {
						result += memory.ReadCStringFromPtr(strPtr)
					}
				case 'p':
					// Pointer
					result += fmt.Sprintf("%p", unsafe.Pointer(args[argOffset]))
				case 'f', 'F', 'e', 'E', 'g', 'G':
					// Float/double
					result += fmt.Sprintf("%"+string(spec), math.Float64frombits(uint64(args[argOffset])))
				case 'n':
					// Ignore
				default:
					// Unknown spec
					result += fmt.Sprintf("%"+string(spec), args[argOffset])
				}

				argOffset++
			}
			i++
		} else {
			result += string(fmtStr[i])
			i++
		}
	}

	return result
}

// GetElfOutputForChannel returns a function pointer for BeaconOutput
func GetElfOutputForChannel(channel chan<- interface{}) func(int, uintptr, int) uintptr {
	return func(beaconType int, data uintptr, length int) uintptr {
		if length <= 0 {
			return 0
		}
		out := memory.ReadBytesFromPtr(data, uint32(length))

		channel <- beaconType
		channel <- []byte(out)
		return 1
	}
}

// GetElfPrintfForChannel returns a function pointer for BeaconPrintf
func GetElfPrintfForChannel(channel chan<- interface{}) func(int, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr, uintptr) uintptr {
	return func(beaconType int, data uintptr, arg0 uintptr, arg1 uintptr, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr, arg6 uintptr, arg7 uintptr, arg8 uintptr, arg9 uintptr) uintptr {
		fmtStr := memory.ReadCStringFromPtr(data)
		args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}

		result := parsePrintfFormat(fmtStr, args)
		channel <- beaconType
		channel <- []byte(result)
		return 0
	}
}

// FormatPrintfFunc implements BeaconFormatPrintf
func FormatPrintfFunc(format *Formatp, fmtPtr uintptr, arg0 uintptr, arg1 uintptr, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr, arg6 uintptr, arg7 uintptr, arg8 uintptr, arg9 uintptr) uintptr {
	if format == nil || format.Original == 0 || fmtPtr == 0 {
		return 0
	}

	fmtStr := memory.ReadCStringFromPtr(fmtPtr)
	if fmtStr == "" {
		return 0
	}

	args := []uintptr{arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9}
	result := parsePrintfFormat(fmtStr, args)

	resultLen := uint32(len(result))
	if format.Length+resultLen > format.Size {
		return 0
	}

	resultBytes := []byte(result)
	for i := uint32(0); i < resultLen; i++ {
		*(*byte)(unsafe.Pointer(format.Buffer + uintptr(i))) = resultBytes[i]
	}

	format.Buffer += uintptr(resultLen)
	format.Length += resultLen
	return 0
}

// DataExtract implements BeaconDataExtract
func DataExtract(datap *Datap, size *uint32) uintptr {
	if datap.Length <= 0 {
		return 0
	}

	binaryLength := *(*uint32)(unsafe.Pointer(datap.Buffer))
	datap.Buffer += uintptr(4)
	datap.Length -= 4
	if datap.Length < binaryLength {
		return 0
	}

	out := make([]byte, binaryLength)
	memory.MemCpy(uintptr(unsafe.Pointer(&out[0])), datap.Buffer, binaryLength)
	if uintptr(unsafe.Pointer(size)) != uintptr(0) && binaryLength != 0 {
		*size = binaryLength
	}

	datap.Buffer += uintptr(binaryLength)
	datap.Length -= binaryLength
	return uintptr(unsafe.Pointer(&out[0]))
}

// DataParse implements BeaconDataParse
func DataParse(datap *Datap, buff uintptr, size uint32) uintptr {
	if size <= 0 {
		return 0
	}
	datap.Original = buff
	datap.Buffer = buff + uintptr(4)
	datap.Length = size - 4
	datap.Size = size - 4
	return 1
}

// DataInt implements BeaconDataInt
func DataInt(datap *Datap) uintptr {
	value := memory.ReadUIntFromPtr(datap.Buffer)
	datap.Buffer += uintptr(4)
	datap.Length -= 4
	return uintptr(value)
}

// DataLength implements BeaconDataLength
func DataLength(datap *Datap) uintptr {
	return uintptr(datap.Length)
}

// DataShort implements BeaconDataShort
func DataShort(datap *Datap) uintptr {
	if datap.Length < 2 {
		return 0
	}

	value := memory.ReadShortFromPtr(datap.Buffer)
	datap.Buffer += uintptr(2)
	datap.Length -= 2
	return uintptr(value)
}

var keyStore = make(map[string]uintptr, 0)

// AddValue implements BeaconAddValue
func AddValue(key uintptr, ptr uintptr) uintptr {
	sKey := memory.ReadCStringFromPtr(key)
	keyStore[sKey] = ptr
	return uintptr(1)
}

// GetValue implements BeaconGetValue
func GetValue(key uintptr) uintptr {
	sKey := memory.ReadCStringFromPtr(key)
	if value, exists := keyStore[sKey]; exists {
		return value
	}
	return uintptr(0)
}

// RemoveValue implements BeaconRemoveValue
func RemoveValue(key uintptr) uintptr {
	sKey := memory.ReadCStringFromPtr(key)
	if _, exists := keyStore[sKey]; exists {
		delete(keyStore, sKey)
		return uintptr(1)
	}
	return uintptr(0)
}

// FormatAllocate implements BeaconFormatAlloc
func FormatAllocate(format *Formatp, maxsz uint32) uintptr {
	if format == nil {
		return 0
	}

	// Use mmap for memory allocation on Linux
	ptr, err := mmapAlloc(uintptr(maxsz))
	if err != nil || ptr == 0 {
		return 0
	}

	format.Original = ptr
	format.Buffer = ptr
	format.Length = 0
	format.Size = maxsz

	return 0
}

// FormatReset implements BeaconFormatReset
func FormatReset(format *Formatp) uintptr {
	if format == nil || format.Original == 0 {
		return 0
	}

	memory.MemSet(format.Original, 0, format.Size)
	format.Buffer = format.Original
	format.Length = format.Size

	return 0
}

// FormatAppend implements BeaconFormatAppend
func FormatAppend(format *Formatp, text uintptr, len uint32) uintptr {
	if format == nil || len <= 0 || text == 0 {
		return 0
	}

	available := format.Size - format.Length
	if len > available {
		len = available
	}

	memory.MemCpy(format.Buffer, text, len)
	format.Buffer += uintptr(len)
	format.Length += len

	return 0
}

// FormatFree implements BeaconFormatFree
func FormatFree(format *Formatp) uintptr {
	if format == nil || format.Original == 0 {
		return 0
	}

	// Unmap memory on Linux
	syscall.Syscall(syscall.SYS_MUNMAP, format.Original, uintptr(format.Size), 0)
	format.Original = 0
	format.Buffer = 0
	format.Length = 0
	format.Size = 0

	return 0
}

// FormatInt implements BeaconFormatInt
func FormatInt(format *Formatp, value int32) uintptr {
	if format == nil {
		return 0
	}

	valueStr := fmt.Sprintf("%d", value)
	valueBytes := []byte(valueStr)
	valueLen := uint32(len(valueBytes))

	if format.Length+valueLen > format.Size {
		return 0
	}

	for i := uint32(0); i < valueLen; i++ {
		*(*byte)(unsafe.Pointer(format.Buffer + uintptr(i))) = valueBytes[i]
	}

	format.Buffer += uintptr(valueLen)
	format.Length += valueLen
	return 0
}

// FormatToString implements BeaconFormatToString
func FormatToString(format *Formatp, buffer uintptr, maxsz uint32) uintptr {
	if format == nil || buffer == 0 {
		return 0
	}

	copyLen := format.Length
	if copyLen > maxsz {
		copyLen = maxsz
	}

	memory.MemCpy(buffer, format.Original, copyLen)
	return uintptr(copyLen)
}

// AxAddScreenshot returns a function pointer for screenshot callback
func AxAddScreenshot(channel chan<- interface{}) func(uintptr, uintptr) uintptr {
	return func(note uintptr, data uintptr) uintptr {
		// Implementation for screenshot callback
		// This would need to be implemented based on specific requirements
		return 0
	}
}

// AxDownloadMemory returns a function pointer for memory download callback
func AxDownloadMemory(channel chan<- interface{}) func(uintptr, uintptr) uintptr {
	return func(filename uintptr, data uintptr) uintptr {
		// Implementation for memory download callback
		// This would need to be implemented based on specific requirements
		return 0
	}
}

// mmapAlloc allocates memory using mmap
func mmapAlloc(size uintptr) (uintptr, error) {
	addr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,
		size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
		^uintptr(0),
		0,
	)

	if errno != 0 {
		return 0, errno
	}

	return addr, nil
}

