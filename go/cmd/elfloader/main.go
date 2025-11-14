package main

import (
	"fmt"
	"os"

	"github.com/Nurdich/ELFLoader/pkg/elfloader"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <path/to/objectfile.o> [hex-encoded-arguments]\n", os.Args[0])
		fmt.Println("\nExample:")
		fmt.Printf("  %s ./example.o\n", os.Args[0])
		fmt.Printf("  %s ./example.o 48656c6c6f\n", os.Args[0])
		os.Exit(1)
	}

	// Read ELF object file
	elfPath := os.Args[1]
	elfData, err := os.ReadFile(elfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading ELF file: %v\n", err)
		os.Exit(1)
	}

	// Parse hex-encoded arguments if provided
	var argumentData []byte
	if len(os.Args) >= 3 {
		hexArgs := os.Args[2]
		argumentData, err = elfloader.Unhexlify(hexArgs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hex arguments: %v\n", err)
			os.Exit(1)
		}
	}

	// Run the ELF object file using the C implementation
	// The function name "go" is the default entry point
	fmt.Println("Loading ELF with C implementation...")
	err = elfloader.ELFRunnerC("go", elfData, argumentData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running ELF file: %v\n", err)
		os.Exit(1)
	}

	// Get and print the output from BeaconPrintf calls
	output, size := elfloader.GetBeaconOutput()
	if size > 0 {
		fmt.Println("\n--- Beacon Output ---")
		fmt.Print(string(output))
		fmt.Println("--- End Output ---")
	}

	fmt.Println("ELF execution completed successfully")
}
