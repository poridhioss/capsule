package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
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
	PIDsMax   int    // process count; 0 = unlimited
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
	if c.PIDsMax > 0 {
		if err := writePidsMax(dir, c.PIDsMax); err != nil {
			return fmt.Errorf("write pids.max: %w", err)
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

// Cleanup signals every process in the cgroup (SIGTERM, then SIGKILL
// after a short grace period), then removes the cgroup directory.
// When the cgroup is already empty the drain is a no-op.
func Cleanup(name string) error {
	dir := filepath.Join(Root, name)

	// 1. Polite stop: SIGTERM to every PID in the cgroup.
	if pids, err := readPids(dir); err == nil && len(pids) > 0 {
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		// 2. Grace period. Well-behaved processes exit during this window.
		time.Sleep(500 * time.Millisecond)

		// 3. Forceful stop: SIGKILL to whoever is still alive.
		if pids, err := readPids(dir); err == nil {
			for _, pid := range pids {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}

	// 4. rmdir. The cgroup should be empty now.
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rmdir %s: %w", dir, err)
	}
	return nil
}

// readPids reads cgroup.procs and returns the PIDs as ints. An empty
// file (no processes) returns an empty slice without error.
func readPids(dir string) ([]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	pids := make([]int, 0, len(fields))
	for _, f := range fields {
		pid, err := strconv.Atoi(f)
		if err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// ensureParent makes /sys/fs/cgroup/capsule/ if it does not exist and
// enables the controllers we use in its subtree_control.
func ensureParent() error {
	if err := os.Mkdir(Root, 0755); err != nil && !os.IsExist(err) {
		return err
	}
	return writeFile(filepath.Join(Root, "cgroup.subtree_control"),
		"+memory +cpu +pids")
}

// writeFile is a thin wrapper around os.WriteFile that the controller files
// share. Cgroup files want a plain string and ignore trailing newlines.
func writeFile(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}