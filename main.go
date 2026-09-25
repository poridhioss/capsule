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
echo ""

echo "--- Alpine Release ---"
cat /etc/alpine-release
echo ""

echo "--- Rootfs Backing (mountinfo for /) ---"
awk '
$5 == "/" {
    for (i = 7; i <= NF; i++) {
        if ($i == "-") {
            print "  type:", $(i + 1), "  source:", $(i + 2)
            exit
        }
    }
}
' /proc/self/mountinfo
echo ""

echo "--- Writable Layer Probe ---"
echo "lab-08 was here" > /marker.txt
echo "  wrote /marker.txt:  $(cat /marker.txt)"
echo ""

echo "--- Copy-Up Probe ---"
echo "  before: $(head -n1 /etc/alpine-release)"
echo "edited by lab-08" > /etc/alpine-release
echo "  after:  $(head -n1 /etc/alpine-release)"
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
	containerName := "demo"
	if v := os.Getenv("CAPSULE_NAME"); v != "" {
		containerName = v
	}

	fmt.Println("=== OverlayFS Layered Container ===")
	fmt.Printf("Parent PID: %d\n", os.Getpid())
	fmt.Printf("Container name: %s\n", containerName)
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

	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		fmt.Fprintf(os.Stderr, "Error unsharing mount ns: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error making root private: %v\n", err)
		os.Exit(1)
	}

	lower, err := filepath.Abs("images/alpine")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving lower path: %v\n", err)
		os.Exit(1)
	}
	base, err := filepath.Abs(filepath.Join("containers", containerName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving container path: %v\n", err)
		os.Exit(1)
	}

	overlay := filesystem.OverlayConfig{
		LowerDirs: []string{lower},
		UpperDir:  filepath.Join(base, "upper"),
		WorkDir:   filepath.Join(base, "work"),
		MergedDir: filepath.Join(base, "merged"),
	}

	hostUID, hostGID := unprivilegedHostIDs()

	// MountOverlay normally creates all three directories. However, upper must
	// already belong to the mapped host user before the overlay is mounted.
	// Otherwise, the first merged-root inode can remain root-owned, preventing
	// container root (mapped to hostUID) from creating /.old_root.
	if err := os.MkdirAll(overlay.UpperDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating upper directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.Chown(overlay.UpperDir, hostUID, hostGID); err != nil {
		fmt.Fprintf(os.Stderr, "Error chowning upper: %v\n", err)
		os.Exit(1)
	}

	if err := filesystem.MountOverlay(overlay); err != nil {
		fmt.Fprintf(os.Stderr, "Error mounting overlay: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := filesystem.UnmountOverlay(overlay.MergedDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to unmount overlay: %v\n", err)
		}
	}()

	// From here on, the merged directory plays the role that the flat rootfs
	// played in Lab 07: bind it onto itself, then stage the virtual filesystems
	// inside it from the parent.
	if err := syscall.Mount(overlay.MergedDir, overlay.MergedDir, "",
		syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error bind-mounting merged: %v\n", err)
		os.Exit(1)
	}
	if err := filesystem.ParentMountAll(overlay.MergedDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error staging mounts in merged: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command("/proc/self/exe", "child", overlay.MergedDir)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	uidMap, gidMap := namespace.DefaultMapping(hostUID, hostGID)
	nsCfg := namespace.Config{
		PID:         true,
		UTS:         true,
		Mount:       true,
		User:        true,
		UIDMap:      uidMap,
		GIDMap:      gidMap,
		AmbientCaps: []uintptr{capSysAdmin},
	}
	nsCfg.Apply(cmd)
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}

	fmt.Printf("Lower:  %s\n", lower)
	fmt.Printf("Upper:  %s\n", overlay.UpperDir)
	fmt.Printf("Merged: %s\n", overlay.MergedDir)
	fmt.Printf("Mapping container UID 0 -> host UID %d\n\n", hostUID)

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
}

func child() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "child: missing merged path argument")
		os.Exit(1)
	}
	merged := os.Args[2]

	if err := syscall.Sethostname([]byte("capsule")); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting hostname: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error making root private: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Mount("proc", merged+"/proc", "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error mounting /proc: %v\n", err)
		os.Exit(1)
	}
	if err := filesystem.PivotRoot(merged); err != nil {
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

func unprivilegedHostIDs() (int, int) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid == 0 || gid == 0 {
		return 65534, 65534
	}
	return uid, gid
}
