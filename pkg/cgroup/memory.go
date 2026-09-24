package cgroup

import (
	"fmt"
	"path/filepath"
)

// writeMemoryMax sets memory.max (and optionally memory.swap.max) for the
// cgroup at dir. mem must be > 0; swap is ignored if 0 (kernel default
// applies, which is "swap allowed up to memory.max"). Pass swap < 0 to
// explicitly disable swap by writing 0.
func writeMemoryMax(dir string, mem, swap int64) error {
	if err := writeFile(filepath.Join(dir, "memory.max"),
		fmt.Sprintf("%d", mem)); err != nil {
		return err
	}
	if swap == 0 {
		return nil
	}
	v := swap
	if v < 0 {
		v = 0
	}
	return writeFile(filepath.Join(dir, "memory.swap.max"),
		fmt.Sprintf("%d", v))
}