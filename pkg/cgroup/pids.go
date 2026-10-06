package cgroup

import (
	"fmt"
	"path/filepath"
)

// writePidsMax sets pids.max for the cgroup at dir. n must be > 0.
// A zero or negative value is a programming error; the caller is
// expected to check Config.PIDsMax before calling this.
func writePidsMax(dir string, n int) error {
	return writeFile(filepath.Join(dir, "pids.max"),
		fmt.Sprintf("%d", n))
}