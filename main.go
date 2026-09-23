package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/poridhioss/capsule/pkg/cgroup"
	"github.com/poridhioss/capsule/pkg/filesystem"
	"github.com/poridhioss/capsule/pkg/namespace"
)

// capSysAdmin is the Linux capability number for CAP_SYS_ADMIN. We pass it as
// an ambient cap so sethostname, mount, and pivot_root still work after exec
// inside the new user namespace.
const capSysAdmin = 21

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

echo "--- User Identity (inside container) ---"
echo "  id:      $(id)"
echo "  whoami:  $(whoami)"
echo "  euid:    $(id -u)"
echo "  egid:    $(id -g)"
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
echo "  pids.max:        $(cat $CG/pids.max)"
echo "  pids.current:    $(cat $CG/pids.current)"
echo "  pids.events:     $(cat $CG/pids.events | tr '\n' ' ')"
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

	cfg := cgroup.Config{
		Name:      cgName,
		MemoryMax: 50 << 20,
		SwapMax:   -1,
		CPUQuota:  50,
		PIDsMax:   64,
	}
	if err := cgroup.Create(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cgroup: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := cgroup.Cleanup(cgName); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to clean up cgroup: %v\n", err)
		}
	}()

	// Give the parent its own mount namespace so the staging mounts below
	// stay scoped and do not leak to the host. Mount root private to stop
	// propagation in either direction.
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		fmt.Fprintf(os.Stderr, "Error unsharing mount ns: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error making root private: %v\n", err)
		os.Exit(1)
	}

	rootfs, err := filepath.Abs("rootfs")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving rootfs path: %v\n", err)
		os.Exit(1)
	}

	// Bind rootfs onto itself so it becomes a separate mount point. Done here
	// in init_user_ns to sidestep the user-namespace bind restriction the
	// child would otherwise hit.
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error bind-mounting rootfs: %v\n", err)
		os.Exit(1)
	}

	// Stage /sys, /sys/fs/cgroup, /dev, /dev/pts INSIDE rootfs from here.
	// The child inherits these via CLONE_NEWNS and only has /proc left to mount.
	if err := filesystem.ParentMountAll(rootfs); err != nil {
		fmt.Fprintf(os.Stderr, "Error staging mounts in rootfs: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command("/proc/self/exe", "child")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	hostUID, hostGID := unprivilegedHostIDs()
	uidMap, gidMap := namespace.DefaultMapping(hostUID, hostGID)

	nsCfg := namespace.Config{
		PID:    true,
		UTS:    true,
		Mount:  true,
		User:   true,
		UIDMap: uidMap,
		GIDMap: gidMap,
		// Without ambient CAP_SYS_ADMIN the child loses caps across exec
		// because the capsule binary is owned by host root, which is not
		// mapped into the new user namespace.
		AmbientCaps: []uintptr{capSysAdmin},
	}
	nsCfg.Apply(cmd)

	// Set the child's UID/GID inside the namespace to 0 before exec. Without
	// this, the child's host UID (0, inherited from sudo) is unmapped in the
	// user namespace and shows up as the overflow UID (65534).
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}

	fmt.Printf("Mapping container UID 0 -> host UID %d\n", hostUID)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting child: %v\n", err)
		os.Exit(1)
	}

	if err := cgroup.AddProcess(cgName, cmd.Process.Pid); err != nil {
		fmt.Fprintf(os.Stderr, "Error adding child to cgroup: %v\n", err)
	}

	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Child exited with error: %v\n", err)
	}
	fmt.Println("Child process exited.")
	fmt.Printf("Parent hostname after child exit: %s\n", host)
}

func child() {
	fmt.Println("--- Running inside new namespaces and rootfs ---")

	if err := syscall.Sethostname([]byte("capsule")); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting hostname: %v\n", err)
		os.Exit(1)
	}

	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error making root private: %v\n", err)
		os.Exit(1)
	}

	rootfs, err := filepath.Abs("rootfs")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving rootfs path: %v\n", err)
		os.Exit(1)
	}

	// /proc must be mounted from inside the child so it reflects the new
	// PID namespace. The parent pre-mounted /sys, /sys/fs/cgroup, /dev, /dev/pts.
	if err := syscall.Mount("proc", rootfs+"/proc", "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error mounting /proc: %v\n", err)
		os.Exit(1)
	}

	if err := filesystem.PivotRoot(rootfs); err != nil {
		fmt.Fprintf(os.Stderr, "Error pivoting root: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command("/bin/sh", "-c", inspectScript)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running inspection: %v\n", err)
	}
}

// Returns SUDO_UID/SUDO_GID, or 65534 (nobody) if either is unset or zero.
func unprivilegedHostIDs() (int, int) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid == 0 || gid == 0 {
		return 65534, 65534
	}
	return uid, gid
}
