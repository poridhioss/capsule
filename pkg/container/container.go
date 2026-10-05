package container

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/poridhioss/capsule/pkg/cgroup"
	"github.com/poridhioss/capsule/pkg/filesystem"
	"github.com/poridhioss/capsule/pkg/image"
	"github.com/poridhioss/capsule/pkg/namespace"
	"github.com/poridhioss/capsule/pkg/network"
	"golang.org/x/sys/unix"
)

type Container struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Image      string                `json:"image"`
	Cmd        []string              `json:"cmd"`
	Env        []string              `json:"env"`
	Mounts     []filesystem.Mount    `json:"mounts,omitempty"`
	Ports      []network.PortMapping `json:"ports,omitempty"`
	Base       string                `json:"base"`
	UID        int                   `json:"host_uid"`
	GID        int                   `json:"host_gid"`
	Grace      time.Duration         `json:"stop_timeout_ns"`
	State      State                 `json:"state"`
	PID        int                   `json:"pid,omitempty"`
	OwnerPID   int                   `json:"owner_pid,omitempty"`
	OwnerStart string                `json:"owner_start,omitempty"`
	BootID     string                `json:"boot_id,omitempty"`
	Created    time.Time             `json:"created"`
	Started    *time.Time            `json:"started,omitempty"`
	Finished   *time.Time            `json:"finished,omitempty"`
	ExitCode   *int                  `json:"exit_code,omitempty"`
	LastError  string                `json:"last_error,omitempty"`
	CleanupOK  bool                  `json:"cleanup_ok"`
}

// Create persists configuration only. Start performs image and kernel setup.
func (c *Container) Create() error {
	c.ID = c.Name // Stable, readable IDs for this stage of the project.
	lock, err := lockContainer(c.ID)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := Load(c.ID); err == nil {
		return fmt.Errorf("container %s exists; use --start or --remove", c.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if c.UID <= 0 || c.GID <= 0 || c.Grace <= 0 || c.Grace > time.Minute {
		return fmt.Errorf("use a normal sudo user and a grace period between 0 and 1 minute")
	}
	if c.Image == "" {
		return fmt.Errorf("image must not be empty")
	}
	if err := filesystem.ValidateMounts(c.Mounts); err != nil {
		return err
	}
	// Relative bind paths must retain their meaning in later SSH sessions.
	for i := range c.Mounts {
		if c.Mounts[i].Kind == filesystem.MountBind {
			c.Mounts[i].Source, err = filepath.Abs(c.Mounts[i].Source)
			if err != nil {
				return err
			}
		}
	}
	c.Env, err = MergeEnv(c.Env)
	if err != nil {
		return err
	}
	c.Base, err = filepath.Abs(filepath.Join("containers", c.ID))
	if err != nil {
		return err
	}
	c.State, c.Created, c.CleanupOK = StateCreated, time.Now().UTC(), true
	if err := os.MkdirAll(filepath.Join(Root, c.ID), 0700); err != nil {
		return err
	}
	return c.Persist()
}

func (c *Container) Start(uid, gid int) (code int, result error) {
	// Unshare and child creation must remain on the same Linux thread.
	runtime.LockOSThread()
	lock, err := lockContainer(c.ID)
	if err != nil {
		return 1, err
	}
	defer lock.Close()
	current, err := Load(c.ID)
	if err != nil {
		return 1, err
	}
	*c = *current
	if c.State != StateCreated && c.State != StateStopped {
		return 1, fmt.Errorf("cannot start container in state %s", c.State)
	}
	if !c.CleanupOK {
		return 1, fmt.Errorf("previous cleanup failed: %s", c.LastError)
	}
	if c.UID != uid || c.GID != gid {
		return 1, fmt.Errorf("start with the same sudo user that created this container")
	}
	c.Started, c.Finished, c.ExitCode = nil, nil, nil
	c.LastError, c.CleanupOK = "", false
	c.OwnerPID, c.PID = 0, 0
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	code, cleanupErr, runErr := c.run(signals)
	result = errors.Join(runErr, cleanupErr)
	if c.State != StateStopped {
		if err := c.transition(StateStopped); err != nil {
			return code, errors.Join(result, err)
		}
	}
	now := time.Now().UTC()
	c.Finished, c.ExitCode = &now, &code
	c.PID, c.OwnerPID, c.OwnerStart, c.BootID = 0, 0, "", ""
	c.CleanupOK = cleanupErr == nil
	if result != nil {
		c.LastError = result.Error()
	}
	result = errors.Join(result, c.Persist())
	fmt.Printf("State: %s\nExit code: %d\n", c.State, code)
	return code, result
}

func (c *Container) Stop() error {
	current, err := Load(c.ID)
	if err != nil {
		return err
	}
	*c = *current
	if c.State == StateStopped && c.CleanupOK {
		return nil
	}
	if c.State != StateRunning {
		return fmt.Errorf("container %s is not running", c.ID)
	}
	if err := signalOwner(c); err != nil {
		return err
	}
	deadline := time.Now().Add(c.Grace + 10*time.Second)
	for time.Now().Before(deadline) {
		current, err = Load(c.ID)
		if err != nil {
			return err
		}
		if current.State == StateStopped {
			*c = *current
			if !c.CleanupOK {
				return fmt.Errorf("container stopped but cleanup failed: %s", c.LastError)
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s to finish cleanup; inspect its parent terminal", c.ID)
}

func (c *Container) Remove() error {
	lock, err := lockContainer(c.ID)
	if err != nil {
		return err // Never remove a container while its foreground owner is active.
	}
	defer lock.Close()
	current, err := Load(c.ID)
	if err != nil {
		return err
	}
	*c = *current
	if c.State != StateCreated && c.State != StateStopped {
		return fmt.Errorf("stop container %s before removing it", c.ID)
	}
	if !c.CleanupOK {
		return fmt.Errorf("refusing removal after incomplete cleanup: %s", c.LastError)
	}
	// Remove only this container's private directory after successful cleanup.
	resolved, err := filepath.EvalSymlinks(c.Base)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if resolved != c.Base {
			return fmt.Errorf("refusing removal through a symlink: %s", c.Base)
		}
		if err := os.RemoveAll(c.Base); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(filepath.Join(Root, c.ID)); err != nil {
		return err
	}
	return c.transition(StateRemoved)
}

func processStart(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	// comm (field 2) can contain spaces and parentheses; starttime is field 22.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", fmt.Errorf("invalid process stat for %d", pid)
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 {
		return "", fmt.Errorf("short process stat for %d", pid)
	}
	return fields[19], nil
}

func bootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(data)), err
}

// A stored PID is not an identity: open a pidfd, then verify this runtime owner.
func signalOwner(c *Container) error {
	if c.OwnerPID <= 1 || c.OwnerStart == "" || c.BootID == "" {
		return fmt.Errorf("container has no recorded runtime owner")
	}
	fd, err := unix.PidfdOpen(c.OwnerPID, 0)
	if err != nil {
		return fmt.Errorf("open runtime owner: %w", err)
	}
	defer unix.Close(fd)
	start, err := processStart(c.OwnerPID)
	if err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if start != c.OwnerStart || boot != c.BootID {
		return fmt.Errorf("stale runtime identity; refusing to signal a reused PID")
	}
	return unix.PidfdSendSignal(fd, syscall.SIGTERM, nil, 0)
}

func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		if status, ok := exited.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		if exited.ExitCode() >= 0 {
			return exited.ExitCode()
		}
	}
	return 1
}

// Normal run path: one Wait goroutine remains active throughout shutdown.
func waitWithSignals(cmd *exec.Cmd, signals <-chan os.Signal, grace time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var timer *time.Timer
	var deadline <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case err := <-done:
			return err
		case sig := <-signals:
			if timer != nil {
				continue // Repeated signals do not restart the grace period.
			}
			fmt.Printf("Shutdown: forwarding %s to container init\n", sig)
			if err := cmd.Process.Signal(sig); err != nil && !errors.Is(err, os.ErrProcessDone) {
				_ = cmd.Process.Kill()
				return errors.Join(err, <-done)
			}
			timer = time.NewTimer(grace)
			deadline = timer.C
		case <-deadline:
			fmt.Println("Shutdown: grace period expired; sending SIGKILL")
			_ = cmd.Process.Kill() // Killing namespace PID 1 terminates its members.
			deadline = nil
		}
	}
}

// PID 1 owns all waits here: reap orphans without racing exec.Cmd.Wait.
func reapWorkload(cmd *exec.Cmd) (int, error) {
	defer cmd.Process.Release()
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 1, err
		}
		if pid != cmd.Process.Pid {
			continue
		}
		if status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return status.ExitStatus(), nil
	}
}

func Child() (int, error) {
	if len(os.Args) < 4 {
		return 1, fmt.Errorf("child: missing merged path or workload")
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	ready, installed := os.NewFile(3, "start-gate"), os.NewFile(4, "signal-ready")
	if ready == nil || installed == nil {
		return 1, fmt.Errorf("child: missing synchronization pipes")
	}
	defer ready.Close()
	if _, err := installed.Write([]byte{1}); err != nil {
		installed.Close()
		return 1, err
	}
	_ = installed.Close()
	var token [1]byte
	if _, err := io.ReadFull(ready, token[:]); err != nil || token[0] != 1 {
		return 1, fmt.Errorf("child: parent did not release the start gate")
	}
	_ = ready.Close()
	merged := os.Args[2]
	if err := syscall.Sethostname([]byte("capsule")); err != nil {
		return 1, err
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return 1, err
	}
	if err := syscall.Mount("proc", filepath.Join(merged, "proc"), "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return 1, err
	}
	if err := filesystem.PivotRoot(merged); err != nil {
		return 1, err
	}
	cmd := exec.Command(os.Args[3], os.Args[4:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ() // Already the explicit, merged container environment.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return superviseWorkload(cmd, signals)
}

func superviseWorkload(cmd *exec.Cmd, signals <-chan os.Signal) (int, error) {
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	workloadPGID := cmd.Process.Pid
	type outcome struct {
		code int
		err  error
	}
	done := make(chan outcome, 1)
	go func() { code, err := reapWorkload(cmd); done <- outcome{code, err} }()
	for {
		select {
		case result := <-done:
			return result.code, result.err
		case sig := <-signals:
			// A negative PID addresses the workload's process group, including
			// ordinary shell children that have not created another group.
			if err := syscall.Kill(-workloadPGID, sig.(syscall.Signal)); err != nil && !errors.Is(err, syscall.ESRCH) {
				return 1, fmt.Errorf("forward signal to workload: %w", err)
			}
		}
	}
}

const (
	capSysAdmin       = 21
	capNetRaw         = 13
	capNetBindService = 10
)

func (c *Container) run(signals <-chan os.Signal) (code int, cleanupErr, runErr error) {
	code = 1
	if runtime.GOARCH != "amd64" {
		return 1, nil, fmt.Errorf("use the x86-64 EC2 lab instance")
	}
	var imageUse *os.File
	var connection *network.Connection
	var cmd *exec.Cmd
	var overlay filesystem.OverlayConfig
	var applied []filesystem.Mount
	var started, waited, overlayMounted, selfBound, cgroupCreated bool
	// One cleanup owner; stopped metadata is written only after this returns.
	defer func() {
		if started && !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if len(applied) > 0 {
			cleanupErr = errors.Join(cleanupErr, filesystem.UnmountVolumes(overlay.MergedDir, applied))
		}
		if selfBound {
			cleanupErr = errors.Join(cleanupErr, syscall.Unmount(overlay.MergedDir, syscall.MNT_DETACH))
		}
		if overlayMounted {
			cleanupErr = errors.Join(cleanupErr, filesystem.UnmountOverlay(overlay.MergedDir))
		}
		if cgroupCreated {
			cleanupErr = errors.Join(cleanupErr, cgroup.Cleanup(c.ID))
		}
		if connection != nil {
			cleanupErr = errors.Join(cleanupErr, connection.Cleanup())
		}
		if imageUse != nil {
			cleanupErr = errors.Join(cleanupErr, imageUse.Close())
		}
	}()

	imageID, lowers, use, err := image.PrepareForRun(image.StoreRoot, c.Image, c.UID, c.GID)
	if err != nil {
		return 1, nil, err
	}
	imageUse = use
	connection, err = network.Reserve(c.ID, c.Ports)
	if err != nil {
		return 1, nil, err
	}
	if err := image.PinContainer(c.Base, imageID); err != nil {
		return 1, nil, err
	}
	overlay = filesystem.OverlayConfig{
		LowerDirs: lowers, UpperDir: filepath.Join(c.Base, "upper"),
		WorkDir: filepath.Join(c.Base, "work"), MergedDir: filepath.Join(c.Base, "merged"),
	}
	dnsFile, err := prepareDNSFile(c.Base)
	if err != nil {
		return 1, nil, err
	}
	specs := append([]filesystem.Mount{{Kind: filesystem.MountBind,
		Source: dnsFile, Target: "/etc/resolv.conf", ReadOnly: true}}, c.Mounts...)
	if err := filesystem.ValidateMounts(specs); err != nil {
		return 1, nil, fmt.Errorf("mount conflicts with runtime DNS: %w", err)
	}
	for i := range specs {
		specs[i].HostUID, specs[i].HostGID = c.UID, c.GID
	}
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		return 1, nil, err
	}
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return 1, nil, err
	}
	if err := os.MkdirAll(overlay.UpperDir, 0755); err != nil {
		return 1, nil, err
	}
	if err := os.Chown(overlay.UpperDir, c.UID, c.GID); err != nil {
		return 1, nil, err
	}
	if err := filesystem.MountOverlay(overlay); err != nil {
		return 1, nil, err
	}
	overlayMounted = true
	if err := syscall.Mount(overlay.MergedDir, overlay.MergedDir, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return 1, nil, err
	}
	selfBound = true
	if err := prepareImageMounts(overlay.MergedDir, c.UID, c.GID); err != nil {
		return 1, nil, err
	}
	if err := filesystem.ParentMountAll(overlay.MergedDir); err != nil {
		return 1, nil, err
	}
	for _, spec := range specs {
		if err := filesystem.Apply(overlay.MergedDir, spec); err != nil {
			return 1, nil, err
		}
		applied = append(applied, spec)
	}
	cgroupCreated = true // Create can fail after partially creating the cgroup.
	if err := cgroup.Create(cgroup.Config{
		Name: c.ID, MemoryMax: 50 << 20, SwapMax: -1, CPUQuota: 50, PIDsMax: 64,
	}); err != nil {
		return 1, nil, err
	}
	workload := c.Cmd
	if len(workload) == 0 {
		workload = []string{"/bin/sh", "-c", inspectScript, "capsule-inspect"}
		for _, spec := range specs {
			workload = append(workload, spec.Target)
		}
	}
	args := append([]string{"child", overlay.MergedDir}, workload...)
	cmd = exec.Command("/proc/self/exe", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = c.Env
	uidMap, gidMap := namespace.DefaultMapping(c.UID, c.GID)
	nsCfg := namespace.Config{
		PID: true, UTS: true, Mount: true, User: true, Net: true,
		UIDMap: uidMap, GIDMap: gidMap,
		AmbientCaps: []uintptr{capSysAdmin, capNetRaw, capNetBindService},
	}
	nsCfg.Apply(cmd)
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return 1, nil, err
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	installedRead, installedWrite, err := os.Pipe()
	if err != nil {
		return 1, nil, err
	}
	defer installedRead.Close()
	defer installedWrite.Close()
	cmd.ExtraFiles = []*os.File{readyRead, installedWrite}

	fmt.Println("=== Container Lifecycle Management ===")
	fmt.Printf("Parent PID: %d\nContainer name: %s\nImage: %s\n", os.Getpid(), c.Name, c.Image)
	fmt.Printf("Upper: %s\nMerged: %s\n", overlay.UpperDir, overlay.MergedDir)
	fmt.Printf("Mapping container UID 0 -> host UID %d\n", c.UID)
	if err := cmd.Start(); err != nil {
		return 1, nil, err
	}
	started = true
	_ = readyRead.Close()
	_ = installedWrite.Close()
	if err := cgroup.AddProcess(c.ID, cmd.Process.Pid); err != nil {
		return 1, nil, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(installedRead, ack[:]); err != nil || ack[0] != 1 {
		return 1, nil, fmt.Errorf("child did not acknowledge signal handlers")
	}
	if err := connection.Setup(cmd.Process.Pid); err != nil {
		return 1, nil, err
	}
	c.OwnerStart, err = processStart(os.Getpid())
	if err != nil {
		return 1, nil, err
	}
	c.BootID, err = bootID()
	if err != nil {
		return 1, nil, err
	}
	c.OwnerPID, c.PID = os.Getpid(), cmd.Process.Pid
	now := time.Now().UTC()
	c.Started = &now
	if err := c.transition(StateRunning); err != nil {
		return 1, nil, err
	}
	if err := c.Persist(); err != nil {
		return 1, nil, err
	}
	fmt.Printf("State: %s\nChild host PID: %d\n", c.State, c.PID)
	fmt.Printf("Bridge: %s (%s)\nContainer IPv4: %s/24\n", network.BridgeName, network.GatewayCIDR, connection.Lease.IP)
	for _, port := range c.Ports {
		fmt.Printf("Published TCP: %d -> %s:%d\n", port.HostPort, connection.Lease.IP, port.ContainerPort)
	}
	if _, err := readyWrite.Write([]byte{1}); err != nil {
		return 1, nil, err
	}
	_ = readyWrite.Close()
	err = waitWithSignals(cmd, signals, c.Grace)
	waited = true
	code = exitStatus(err)
	if err == nil {
		fmt.Println("Child process exited.")
	}
	return code, nil, err
}

// A per-container host file is mounted read-only at /etc/resolv.conf.
func prepareDNSFile(base string) (string, error) {
	name := filepath.Join(base, "resolv.conf")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return "", err
	}
	if err := f.Chmod(0644); err != nil {
		f.Close()
		return "", err
	}
	_, writeErr := f.WriteString("nameserver 8.8.8.8\noptions timeout:2 attempts:2\n")
	closeErr := f.Close()
	return name, errors.Join(writeErr, closeErr)
}

// An image must not redirect a privileged staging mount through a symlink.
func prepareImageMounts(root string, uid, gid int) error {
	for _, name := range []string{"proc", "sys", "dev", ".old_root"} {
		full := filepath.Join(root, name)
		info, err := os.Lstat(full)
		if errors.Is(err, os.ErrNotExist) {
			if name == ".old_root" {
				continue
			} // PivotRoot creates this later.
			if err := os.Mkdir(full, 0755); err != nil {
				return err
			}
			if err := os.Chown(full, uid, gid); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("image mount target /%s must be a real directory", name)
		}
	}
	return nil
}

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
if [ -f /etc/alpine-release ]; then
    cat /etc/alpine-release
else
    echo "  this image is not Alpine"
fi
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
echo "lab-13 was here" > /marker.txt
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

echo "--- Network Interfaces ---"
ip link show
echo ""

echo "--- IPv4 Addresses ---"
ip -4 addr show
echo ""

echo "--- IPv4 Routes ---"
ip -4 route show
echo ""

echo "--- DNS Configuration ---"
cat /etc/resolv.conf
echo ""

echo "========== END INSPECTION =========="
`
