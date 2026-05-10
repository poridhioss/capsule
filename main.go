package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	
	"github.com/poridhioss/capsule/pkg/cgroup"
	"github.com/poridhioss/capsule/pkg/filesystem"
)

const inspectScript = `
echo "========== CHILD PROCESS INSPECTION =========="
echo ""

echo "--- Process Identity ---"
echo "  PID:  $$"
echo "  PPID: $(grep PPid /proc/$$/status | awk '{print $2}')"
echo ""

echo "--- Hostname ---"
echo "  $(hostname)"
echo ""

if [ -f /etc/alpine-release ]; then
  echo "--- Alpine Release ---"
  cat /etc/alpine-release
  echo ""
fi

echo "--- Process Table (ps) ---"
ps
echo ""

echo "--- Cgroup Membership ---"
cat /proc/1/cgroup
echo ""

echo "--- Cgroup Limits and Usage ---"
CG=/sys/fs/cgroup/capsule/demo
echo "  memory.max:      $(cat $CG/memory.max)"
echo "  memory.swap.max: $(cat $CG/memory.swap.max)"
echo "  memory.current:  $(cat $CG/memory.current)"
echo "  cpu.max:         $(cat $CG/cpu.max)"
echo "  cpu.stat (head):"
head -n 3 $CG/cpu.stat | sed 's/^/    /'
echo ""

echo "========== END INSPECTION =========="
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		child()
		return
	}
	parent()
}

func parent() {
	const cgName = "demo"

	fmt.Println("=== Process Isolation with Namespaces ===")
	fmt.Printf("Parent PID: %d\n", os.Getpid())
	host, _ := os.Hostname()
	fmt.Printf("Parent hostname: %s\n", host)
	fmt.Println()

	// Create the cgroup before the child starts, so its limits are already
	// in place when we move the child into it.
	cfg := cgroup.Config{
		Name:      cgName,
		MemoryMax: 50 << 20, // 50 MB
		SwapMax:   -1,       // disable swap so memory.max is hard
		CPUQuota:  50,       // 50% of one CPU
	}
	if err := cgroup.Create(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cgroup: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := cgroup.Remove(cgName); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove cgroup: %v\n", err)
		}
	}()

	cmd := exec.Command("/proc/self/exe", "child")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWNS,
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting child: %v\n", err)
		os.Exit(1)
	}

	// Move the child into the cgroup. From now on the kernel charges all
	// memory and CPU the child consumes against the limits set above.
	if err := cgroup.AddProcess(cgName, cmd.Process.Pid); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding child to cgroup: %v\n", err)
		// The child is already running; let it finish so we can clean up.
	}

	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Child exited with error: %v\n", err)
	}
	fmt.Println("Child process exited.")
	fmt.Printf("Parent hostname after child exit: %s\n", host)
}

func child() {
	fmt.Println("--- Running inside new namespaces and rootfs ---")

	// Set hostname in the new UTS namespace.
	if err := syscall.Sethostname([]byte("capsule")); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting hostname: %v\n", err)
		os.Exit(1)
	}

	// Make root mount private to prevent mount propagation to host.
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error making root private: %v\n", err)
		os.Exit(1)
	}

	// Resolve the absolute path to ./rootfs so pivot_root sees a real path.
	rootfs, err := filepath.Abs("rootfs")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving rootfs path: %v\n", err)
		os.Exit(1)
	}

	// Pivot into the Alpine rootfs.
	if err := filesystem.PivotRoot(rootfs); err != nil {
		fmt.Fprintf(os.Stderr, "Error pivoting root: %v\n", err)
		os.Exit(1)
	}

	// Mount /proc, /sys, /dev (with device nodes and symlinks), and /dev/pts.
	if err := filesystem.MountAll(); err != nil {
		fmt.Fprintf(os.Stderr, "Error mounting virtual filesystems: %v\n", err)
		os.Exit(1)
	}

	// Run the inspection script using the rootfs's /bin/sh (busybox ash).
	cmd := exec.Command("/bin/sh", "-c", inspectScript)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running inspection: %v\n", err)
	}

	if err := filesystem.UnmountAll(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to unmount: %v\n", err)
	}
}
