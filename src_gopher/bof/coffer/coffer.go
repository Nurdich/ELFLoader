//go:build !windows && !linux

package coffer

import (
	"fmt"
	"gopher/utils"
)

// Dummy function for unsupported platforms
func Load(coffBytes []byte, argBytes []byte) ([]utils.BofMsg, error) {
	return []utils.BofMsg{}, fmt.Errorf("BOF loading not supported on this platform")
}
