package filesystem

import (
	"fmt"
	"os"
	"syscall"
)

// devNode describes a character device to be created with mknod under /dev.
type devNode struct {
	path  string
	mode  uint32
	major uint32
	minor uint32
}

// defaultDevNodes is the set of device nodes every container is expected to have.
// Major and minor numbers are fixed by the Linux kernel and documented in
// Documentation/admin-guide/devices.txt.
var defaultDevNodes = []devNode{
	{"/dev/null", 0666, 1, 3},
	{"/dev/zero", 0666, 1, 5},
	{"/dev/random", 0666, 1, 8},
	{"/dev/urandom", 0666, 1, 9},
	{"/dev/tty", 0666, 5, 0},
}

// devSymlinks are the standard /dev symlinks that point into /proc/self/fd.
var devSymlinks = []struct {
	target string
	link   string
}{
	{"/proc/self/fd", "/dev/fd"},
	{"/proc/self/fd/0", "/dev/stdin"},
	{"/proc/self/fd/1", "/dev/stdout"},
	{"/proc/self/fd/2", "/dev/stderr"},
}

// MountAll wires up /proc, /sys, /dev (with device nodes), and /dev/pts.
// It must be called after PivotRoot, inside the container's mount namespace,
// while running as root.
func MountAll() error {
	// /proc: process info, scoped to the container's PID namespace.
	if err := syscall.Mount("proc", "/proc", "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}

	// /sys: kernel parameters and device tree, mounted read-only.
	if err := syscall.Mount("sysfs", "/sys", "sysfs",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount /sys: %w", err)
	}

	// /sys/fs/cgroup: cgroup v2 hierarchy, read-only. Lets the container
	// read its own limits and usage; the parent writes them from the host.
	if err := syscall.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount /sys/fs/cgroup: %w", err)
	}

	// /dev: fresh tmpfs, populated with the device nodes a container needs.
	if err := syscall.Mount("tmpfs", "/dev", "tmpfs",
		syscall.MS_NOSUID|syscall.MS_STRICTATIME, "mode=755"); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}

	// Create the standard character device nodes.
	for _, d := range defaultDevNodes {
		dev := int((d.major << 8) | d.minor)
		if err := syscall.Mknod(d.path, syscall.S_IFCHR|d.mode, dev); err != nil {
			return fmt.Errorf("mknod %s: %w", d.path, err)
		}
	}

	// Add /dev/{fd,stdin,stdout,stderr} symlinks pointing into /proc/self/fd.
	for _, s := range devSymlinks {
		if err := os.Symlink(s.target, s.link); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", s.link, s.target, err)
		}
	}

	// /dev/pts: devpts for pseudo-terminals (interactive shells).
	if err := os.MkdirAll("/dev/pts", 0755); err != nil {
		return fmt.Errorf("mkdir /dev/pts: %w", err)
	}
	if err := syscall.Mount("devpts", "/dev/pts", "devpts", 0,
		"newinstance,ptmxmode=0666"); err != nil {
		return fmt.Errorf("mount /dev/pts: %w", err)
	}

	// /dev/ptmx is the PTY multiplexer. With newinstance devpts, the per-mount
	// ptmx lives at /dev/pts/ptmx; programs that open /dev/ptmx directly need
	// a symlink to find it.
	if err := os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil {
		return fmt.Errorf("symlink /dev/ptmx: %w", err)
	}

	return nil
}

// UnmountAll tears down the mounts created by MountAll, in reverse order.
// The kernel will also clean these up when the mount namespace is destroyed at
// child exit, but explicit cleanup keeps the mount table tidy and surfaces
// errors that would otherwise be silent.
func UnmountAll() error {
	mounts := []string{"/dev/pts", "/dev", "/sys/fs/cgroup", "/sys", "/proc"}
	for _, m := range mounts {
		if err := syscall.Unmount(m, syscall.MNT_DETACH); err != nil {
			return fmt.Errorf("unmount %s: %w", m, err)
		}
	}
	return nil
}