package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/poridhioss/capsule/pkg/cgroup"
	"github.com/poridhioss/capsule/pkg/filesystem"
	"github.com/poridhioss/capsule/pkg/namespace"
)

const capSysAdmin = 21

const inspectScript = `
set -e

echo "========== CHILD PROCESS INSPECTION =========="
echo ""

echo "--- Process Identity ---"
echo "  PID:  $$"
echo "  PPID: $(awk '/^PPid:/ {print $2}' /proc/$$/status)"
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
echo "lab-09 was here" > /marker.txt
echo "  wrote /marker.txt:  $(cat /marker.txt)"
echo ""

echo "--- Storage Mounts ---"
if [ "$#" -eq 0 ]; then
    echo "  no additional mounts requested"
fi
for target do
    awk -v target="$target" '
    $5 == target {
        for (i = 7; i <= NF; i++) {
            if ($i == "-") {
                print "  target:", $5, " type:", $(i + 1), " options:", $6
                exit
            }
        }
    }' /proc/self/mountinfo
done
echo ""

# Check the mount table, not just a directory left in an earlier upper layer.
mounted() {
    awk -v target="$1" '
        $5 == target { found = 1 }
        END { exit !found }
    ' /proc/self/mountinfo
}

if mounted /host-data; then
    echo "--- Bind Mount Probe ---"
    if [ -f /host-data/input.txt ]; then
        cat /host-data/input.txt
    fi
    echo "written by container" > /host-data/from-container.txt
    echo "  wrote /host-data/from-container.txt"
    echo ""
fi

if mounted /data; then
    echo "--- Named Volume Probe ---"
    if [ -f /data/message.txt ]; then
        echo "  found existing volume data"
    else
        echo "persistent data from lab-09" > /data/message.txt
        echo "  created volume data"
    fi
    cat /data/message.txt
    echo ""
fi

if mounted /cache; then
    echo "--- tmpfs Probe ---"
    test ! -e /cache/temporary.txt
    echo "  cache starts empty"
    echo "temporary data" > /cache/temporary.txt
    cat /cache/temporary.txt
    echo ""
fi

if mounted /config/app.conf; then
    echo "--- Read-Only Bind Probe ---"
    cat /config/app.conf
    if (echo "unexpected change" >> /config/app.conf) 2>/tmp/readonly-error; then
        echo "ERROR: the read-only bind accepted a write"
        exit 1
    fi
    grep -qi "read-only file system" /tmp/readonly-error
    echo "  write blocked: read-only filesystem"
    echo ""
fi

echo "========== END INSPECTION =========="
`

// Each occurrence of -v or --tmpfs appends one parsed mount specification.
type mountFlag struct {
	specs *[]filesystem.Mount
	parse func(string) (filesystem.Mount, error)
}

func (f mountFlag) String() string { return "" }

func (f mountFlag) Set(value string) error {
	spec, err := f.parse(value)
	if err != nil {
		return err
	}
	*f.specs = append(*f.specs, spec)
	return nil
}

func main() {
	// Namespace changes and the subsequent child creation must use one OS thread.
	runtime.LockOSThread()

	var err error
	if len(os.Args) > 1 && os.Args[1] == "child" {
		err = child()
	} else {
		err = parent()
	}
	// parent/child return first, so their deferred cleanup runs before os.Exit.
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "capsule:", err)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func parent() (result error) {
	var specs []filesystem.Mount
	flags := flag.NewFlagSet("capsule", flag.ContinueOnError)
	flags.Var(mountFlag{&specs, filesystem.ParseVolume}, "v", "source:/target[:ro|rw]")
	flags.Var(mountFlag{&specs, filesystem.ParseTmpfs}, "tmpfs", "/target[:size=16m,mode=1777]")
	createVolume := flags.String("volume-create", "", "create or reuse a named volume")
	listVolumes := flags.Bool("volume-list", false, "list named volumes and their host paths")
	removeVolume := flags.String("volume-remove", "", "remove an unused named volume and its data")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if err := filesystem.ValidateMounts(specs); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run capsule with sudo from your normal user account")
	}

	hostUID, hostGID := unprivilegedHostIDs()
	actions := 0
	for _, enabled := range []bool{*createVolume != "", *listVolumes, *removeVolume != ""} {
		if enabled {
			actions++
		}
	}
	if actions > 1 || (actions == 1 && (len(specs) != 0 || len(flags.Args()) != 0)) {
		return fmt.Errorf("use one volume-management flag without mounts or a workload")
	}
	if *createVolume != "" {
		dir, err := filesystem.CreateNamedVolume(*createVolume, hostUID, hostGID)
		if err != nil {
			return err
		}
		fmt.Printf("Volume ready: %s\nPath: %s\n", *createVolume, dir)
		return nil
	}
	if *listVolumes {
		names, err := filesystem.ListVolumes()
		if err != nil {
			return err
		}
		fmt.Println("NAME\tPATH")
		for _, name := range names {
			fmt.Printf("%s\t%s\n", name, filepath.Join(filesystem.VolumeRoot, name))
		}
		return nil
	}
	if *removeVolume != "" {
		if err := filesystem.RemoveNamedVolume(*removeVolume); err != nil {
			return err
		}
		fmt.Printf("Removed volume: %s\n", *removeVolume)
		return nil
	}

	containerName := os.Getenv("CAPSULE_NAME")
	if containerName == "" {
		containerName = "demo"
	}
	if err := filesystem.ValidateName(containerName); err != nil {
		return err
	}
	lower, err := filepath.Abs("images/alpine")
	if err != nil {
		return err
	}
	base, err := filepath.Abs(filepath.Join("containers", containerName))
	if err != nil {
		return err
	}
	overlay := filesystem.OverlayConfig{
		LowerDirs: []string{lower},
		UpperDir:  filepath.Join(base, "upper"),
		WorkDir:   filepath.Join(base, "work"),
		MergedDir: filepath.Join(base, "merged"),
	}

	for i := range specs {
		specs[i].HostUID = hostUID
		specs[i].HostGID = hostGID
	}

	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount namespace: %w", err)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}

	// Keep the Lab 08 fix: set upper ownership BEFORE mounting OverlayFS.
	if err := os.MkdirAll(overlay.UpperDir, 0755); err != nil {
		return err
	}
	if err := os.Chown(overlay.UpperDir, hostUID, hostGID); err != nil {
		return err
	}
	if err := filesystem.MountOverlay(overlay); err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, filesystem.UnmountOverlay(overlay.MergedDir))
	}()

	if err := syscall.Mount(overlay.MergedDir, overlay.MergedDir, "",
		syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind merged: %w", err)
	}
	defer func() {
		// Detach this self-bind and its staged virtual-filesystem submounts.
		result = errors.Join(result, syscall.Unmount(overlay.MergedDir, syscall.MNT_DETACH))
	}()
	if err := filesystem.ParentMountAll(overlay.MergedDir); err != nil {
		return err
	}

	var applied []filesystem.Mount
	defer func() {
		result = errors.Join(result, filesystem.UnmountVolumes(overlay.MergedDir, applied))
	}()
	for _, spec := range specs {
		if err := filesystem.Apply(overlay.MergedDir, spec); err != nil {
			return err
		}
		applied = append(applied, spec)
	}

	defer func() {
		result = errors.Join(result, cgroup.Cleanup(containerName))
	}()
	if err := cgroup.Create(cgroup.Config{
		Name:      containerName,
		MemoryMax: 50 << 20,
		SwapMax:   -1,
		CPUQuota:  50,
		PIDsMax:   64,
	}); err != nil {
		return fmt.Errorf("create cgroup: %w", err)
	}

	// No command means the familiar inspection script. Tests can pass a
	// specific command after -- without editing and rebuilding main.go.
	workload := flags.Args()
	if len(workload) == 0 {
		workload = []string{"/bin/sh", "-c", inspectScript, "capsule-inspect"}
		for _, spec := range specs {
			workload = append(workload, spec.Target)
		}
	}
	args := append([]string{"child", overlay.MergedDir}, workload...)
	cmd := exec.Command("/proc/self/exe", args...)
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
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: 0, Gid: 0, NoSetGroups: true,
	}

	// The child's first application step is to wait on FD 3. The parent
	// releases it only after cgroup.AddProcess succeeds.
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	cmd.ExtraFiles = []*os.File{readyRead}

	fmt.Println("=== Volumes and Bind Mounts ===")
	fmt.Printf("Parent PID: %d\n", os.Getpid())
	fmt.Printf("Container name: %s\n\n", containerName)
	fmt.Printf("Lower:  %s\n", lower)
	fmt.Printf("Upper:  %s\n", overlay.UpperDir)
	fmt.Printf("Merged: %s\n", overlay.MergedDir)
	fmt.Printf("Mapping container UID 0 -> host UID %d\n\n", hostUID)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start child: %w", err)
	}
	_ = readyRead.Close()
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := cgroup.AddProcess(containerName, cmd.Process.Pid); err != nil {
		return fmt.Errorf("add child to cgroup: %w", err)
	}
	if _, err := readyWrite.Write([]byte{1}); err != nil {
		return fmt.Errorf("release child: %w", err)
	}
	_ = readyWrite.Close()
	err = cmd.Wait()
	waited = true
	if err != nil {
		return fmt.Errorf("child exited: %w", err)
	}
	fmt.Println("Child process exited.")
	return nil
}

func child() error {
	if len(os.Args) < 4 {
		return fmt.Errorf("child: missing merged path or workload")
	}
	ready := os.NewFile(3, "start-gate")
	if ready == nil {
		return fmt.Errorf("child: missing start gate")
	}
	var token [1]byte
	_, err := io.ReadFull(ready, token[:])
	_ = ready.Close()
	if err != nil || token[0] != 1 {
		return fmt.Errorf("child: parent did not release start gate")
	}
	merged := os.Args[2]
	if err := syscall.Sethostname([]byte("capsule")); err != nil {
		return fmt.Errorf("set hostname: %w", err)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("make child mounts private: %w", err)
	}
	if err := syscall.Mount("proc", filepath.Join(merged, "proc"), "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	if err := filesystem.PivotRoot(merged); err != nil {
		return fmt.Errorf("pivot root: %w", err)
	}

	cmd := exec.Command(os.Args[3], os.Args[4:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func unprivilegedHostIDs() (int, int) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 {
		return 65534, 65534
	}
	return uid, gid
}
