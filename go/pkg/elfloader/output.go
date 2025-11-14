package elfloader

import "github.com/Nurdich/ELFLoader/pkg/beacon"

// GetBeaconOutput retrieves the accumulated beacon output
func GetBeaconOutput() ([]byte, int) {
	return beacon.BeaconGetOutputData()
}
