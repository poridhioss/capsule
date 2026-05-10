package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

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

echo "--- /dev contents ---"
ls /dev
echo ""

echo "--- /sys top-level ---"
ls /sys
echo ""

echo "--- /dev/null discards output ---"
echo "hello" > /dev/null && echo "  write to /dev/null OK"
echo ""

echo "--- /dev/urandom yields random bytes ---"
head -c 8 /dev/urandom | od -An -tx1
echo ""

echo "--- /dev/pts is a devpts mount ---"
grep "devpts" /proc/self/mounts || echo "  devpts not found (unexpected)"
echo ""

echo "--- Mount Table ---"
cat /proc/self/mounts
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
	fmt.Println("=== Process Isolation with Namespaces ===")
	fmt.Printf("Parent PID: %d\n", os.Getpid())
	hostname, _ := os.Hostname()
	fmt.Printf("Parent hostname: %s\n\n", hostname)

	cmd := exec.Command("/proc/self/exe", "child")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWNS,
	}

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running child process: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nChild process exited.")
	hostname, _ = os.Hostname()
	fmt.Printf("Parent hostname after child exit: %s\n", hostname)
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
