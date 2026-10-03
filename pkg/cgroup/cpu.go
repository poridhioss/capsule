package cgroup

import (
	"fmt"
	"path/filepath"
)

// cpuPeriod is the throttling window in microseconds. 100 ms is the kernel
// default and the convention every container runtime uses.
const cpuPeriod = 100000

// writeCPUMax translates a percent quota (50 = 50% of one core, 200 = two
// full cores) into the "quota period" two-number format cpu.max expects.
func writeCPUMax(dir string, quotaPct int) error {
	quota := cpuPeriod * quotaPct / 100
	return writeFile(filepath.Join(dir, "cpu.max"),
		fmt.Sprintf("%d %d", quota, cpuPeriod))
}