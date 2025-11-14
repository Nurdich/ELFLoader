package beacon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync"
)

// DataParser represents a data parser for Beacon data
type DataParser struct {
	Original []byte
	Buffer   []byte
	Length   int
	Size     int
}

// FormatBuffer represents a format buffer for Beacon output
type FormatBuffer struct {
	Original []byte
	Buffer   *bytes.Buffer
	Length   int
	Size     int
}

var (
	outputBuffer      bytes.Buffer
	outputMutex       sync.Mutex
	beaconEnviron     = os.Environ()
)

// BeaconDataParse initializes a data parser
func BeaconDataParse(parser *DataParser, buffer []byte, size int) {
	if parser == nil {
		return
	}
	parser.Original = buffer
	parser.Size = size - 4
	parser.Length = size - 4
	if len(buffer) > 4 {
		parser.Buffer = buffer[4:]
	} else {
		parser.Buffer = []byte{}
	}
}

// BeaconDataInt extracts a 4-byte integer from the parser
func BeaconDataInt(parser *DataParser) int32 {
	if parser.Length < 4 {
		return 0
	}
	var value int32
	binary.Read(bytes.NewReader(parser.Buffer[:4]), binary.LittleEndian, &value)
	parser.Buffer = parser.Buffer[4:]
	parser.Length -= 4
	return value
}

// BeaconDataShort extracts a 2-byte short from the parser
func BeaconDataShort(parser *DataParser) int16 {
	if parser.Length < 2 {
		return 0
	}
	var value int16
	binary.Read(bytes.NewReader(parser.Buffer[:2]), binary.LittleEndian, &value)
	parser.Buffer = parser.Buffer[2:]
	parser.Length -= 2
	return value
}

// BeaconDataLength returns the remaining length
func BeaconDataLength(parser *DataParser) int {
	return parser.Length
}

// BeaconDataExtract extracts a length-prefixed binary blob
func BeaconDataExtract(parser *DataParser) ([]byte, int) {
	if parser.Length < 4 {
		return nil, 0
	}
	var length uint32
	binary.Read(bytes.NewReader(parser.Buffer[:4]), binary.LittleEndian, &length)
	parser.Buffer = parser.Buffer[4:]
	parser.Length -= 4

	if parser.Length < int(length) {
		return nil, 0
	}

	outdata := parser.Buffer[:length]
	parser.Buffer = parser.Buffer[length:]
	parser.Length -= int(length)
	return outdata, int(length)
}

// BeaconFormatAlloc allocates a format buffer
func BeaconFormatAlloc(format *FormatBuffer, maxsz int) {
	if format == nil {
		return
	}
	format.Original = make([]byte, maxsz)
	format.Buffer = bytes.NewBuffer(make([]byte, 0, maxsz))
	format.Length = 0
	format.Size = maxsz
}

// BeaconFormatReset resets the format buffer
func BeaconFormatReset(format *FormatBuffer) {
	if format == nil {
		return
	}
	format.Buffer.Reset()
	format.Length = 0
}

// BeaconFormatFree frees the format buffer
func BeaconFormatFree(format *FormatBuffer) {
	if format == nil {
		return
	}
	format.Original = nil
	format.Buffer = nil
	format.Length = 0
	format.Size = 0
}

// BeaconFormatAppend appends data to the format buffer
func BeaconFormatAppend(format *FormatBuffer, text []byte) {
	if format == nil {
		return
	}
	format.Buffer.Write(text)
	format.Length += len(text)
}

// BeaconFormatPrintf formats and appends data to the format buffer
func BeaconFormatPrintf(format *FormatBuffer, fmtStr string, args ...interface{}) {
	if format == nil {
		return
	}
	text := fmt.Sprintf(fmtStr, args...)
	format.Buffer.WriteString(text)
	format.Length += len(text)
}

// BeaconFormatToString returns the format buffer as a string
func BeaconFormatToString(format *FormatBuffer) ([]byte, int) {
	if format == nil {
		return nil, 0
	}
	return format.Buffer.Bytes(), format.Length
}

// BeaconFormatInt appends a big-endian integer to the format buffer
func BeaconFormatInt(format *FormatBuffer, value int32) {
	if format == nil || format.Length+4 > format.Size {
		return
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(value))
	format.Buffer.Write(buf)
	format.Length += 4
}

// BeaconPrintf outputs formatted text to the beacon output buffer
func BeaconPrintf(outputType int, fmtStr string, args ...interface{}) {
	outputMutex.Lock()
	defer outputMutex.Unlock()

	text := fmt.Sprintf(fmtStr, args...)
	outputBuffer.WriteString(text)
}

// BeaconOutput outputs raw data to the beacon output buffer
func BeaconOutput(outputType int, data []byte) {
	outputMutex.Lock()
	defer outputMutex.Unlock()

	outputBuffer.Write(data)
}

// BeaconIsAdmin checks if the current process has admin privileges
func BeaconIsAdmin() int {
	// Simplified implementation - would need platform-specific checks
	return 0
}

// BeaconGetOutputData returns the accumulated output data and clears the buffer
func BeaconGetOutputData() ([]byte, int) {
	outputMutex.Lock()
	defer outputMutex.Unlock()

	data := outputBuffer.Bytes()
	size := outputBuffer.Len()
	outputBuffer.Reset()

	result := make([]byte, size)
	copy(result, data)
	return result, size
}

// GetEnviron returns the environment variables
func GetEnviron() []string {
	return beaconEnviron
}

// GetOSName returns the operating system name
func GetOSName() string {
	switch runtime.GOOS {
	case "darwin":
		return "apple"
	case "freebsd":
		return "freebsd"
	case "openbsd":
		return "openbsd"
	case "linux":
		return "lin"
	default:
		return "unk"
	}
}

// SwapEndianness swaps the endianness of a 32-bit integer
func SwapEndianness(indata uint32) uint32 {
	return ((indata & 0xFF000000) >> 24) |
		((indata & 0x00FF0000) >> 8) |
		((indata & 0x0000FF00) << 8) |
		((indata & 0x000000FF) << 24)
}
