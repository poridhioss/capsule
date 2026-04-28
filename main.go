package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
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

echo "--- Filesystem Root ---"
ls /
echo ""

echo "--- Mount Table (first 10 entries) ---"
cat /proc/self/mounts | head -10
echo ""

echo "--- Network Interfaces ---"
cat /proc/net/dev | head -5
echo ""

echo "========== END INSPECTION =========="
sleep 60
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
	fmt.Println("--- Running inside new namespaces ---")

	// Set hostname in the new UTS namespace
	if err := syscall.Sethostname([]byte("capsule")); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting hostname: %v\n", err)
		os.Exit(1)
	}

	// Make root mount private to prevent mount propagation
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error making root private: %v\n", err)
		os.Exit(1)
	}

	// Mount a fresh /proc to reflect the new PID namespace
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error mounting /proc: %v\n", err)
		os.Exit(1)
	}

	// Run the inspection script
	cmd := exec.Command("/bin/sh", "-c", inspectScript)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running inspection: %v\n", err)
	}

	// Unmount /proc before exiting to restore parent's view
	if err := syscall.Unmount("/proc", 0); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to unmount /proc: %v\n", err)
	}
}
