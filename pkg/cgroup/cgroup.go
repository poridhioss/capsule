package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Root is the parent directory under /sys/fs/cgroup that holds every
// per-container cgroup created by the runtime.
const Root = "/sys/fs/cgroup/capsule"

// Config describes the limits applied to a single container's cgroup.
// A zero value for any limit means "no limit for this resource".
type Config struct {
	Name      string // cgroup directory name under Root
	MemoryMax int64  // bytes; 0 = unlimited
	SwapMax   int64  // bytes; 0 = unlimited (use a negative value for "disable swap")
	CPUQuota  int    // percent of one CPU; 0 = unlimited; 50 = half a core; 200 = two cores
}

// Create makes the cgroup directory under Root and writes the requested limits.
// The parent (capsule/) is created on demand and has +memory +cpu enabled in
// its subtree_control so the child cgroup inherits both controllers.
func Create(c Config) error {
	if err := ensureParent(); err != nil {
		return fmt.Errorf("ensure parent: %w", err)
	}

	dir := filepath.Join(Root, c.Name)
	if err := os.Mkdir(dir, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if c.MemoryMax > 0 {
		if err := writeMemoryMax(dir, c.MemoryMax, c.SwapMax); err != nil {
			return fmt.Errorf("write memory.max: %w", err)
		}
	}
	if c.CPUQuota > 0 {
		if err := writeCPUMax(dir, c.CPUQuota); err != nil {
			return fmt.Errorf("write cpu.max: %w", err)
		}
	}
	return nil
}

// AddProcess writes pid into <Root>/<name>/cgroup.procs, moving the process
// (and any threads it spawns afterwards) into the cgroup.
func AddProcess(name string, pid int) error {
	path := filepath.Join(Root, name, "cgroup.procs")
	return os.WriteFile(path, []byte(strconv.Itoa(pid)), 0644)
}

// Remove deletes the cgroup directory. The cgroup must be empty
// (cgroup.procs has no PIDs) or rmdir returns EBUSY. For Lab 05 the
// child has exited by the time we call Remove, so the cgroup is empty.
// Lab 06 replaces this with a more robust Cleanup that drains lingering PIDs.
func Remove(name string) error {
	dir := filepath.Join(Root, name)
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rmdir %s: %w", dir, err)
	}
	return nil
}

// ensureParent makes /sys/fs/cgroup/capsule/ if it does not exist and
// enables the controllers we use in its subtree_control.
func ensureParent() error {
	if err := os.Mkdir(Root, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	// "+memory +cpu" tells the kernel to make those controllers available
	// inside the children of Root.
	return writeFile(filepath.Join(Root, "cgroup.subtree_control"), "+memory +cpu")
}

// writeFile is a thin wrapper around os.WriteFile that the controller files
// share. Cgroup files want a plain string and ignore trailing newlines.
func writeFile(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}