package container

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Pin the selected process's /proc directory before following its root link.
func openRunningRoot(c *Container) (*os.Root, error) {
	current, err := Load(c.ID)
	if err != nil {
		return nil, err
	}
	*c = *current
	if c.State != StateRunning || c.PID <= 1 || c.InitStart == "" {
		return nil, fmt.Errorf("copy requires a running container with a ready rootfs")
	}
	proc, err := os.Open(fmt.Sprintf("/proc/%d", c.PID))
	if err != nil {
		return nil, err
	}
	defer proc.Close()
	start, err := processStart(c.PID)
	if err != nil {
		return nil, err
	}
	boot, err := bootID()
	if err != nil {
		return nil, err
	}
	if start != c.InitStart || boot != c.BootID {
		return nil, fmt.Errorf("stale container process identity; refusing copy")
	}
	fd, err := unix.Openat(int(proc.Fd()), "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
}

func copyPath(name string) (string, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == "/" {
		return "", fmt.Errorf("use a clean absolute container file path, such as /tmp/input.txt")
	}
	return strings.TrimPrefix(name, "/"), nil
}

// This lab copies regular files. Destination parent directories must exist.
func CopyToContainer(c *Container, hostPath, containerPath string) error {
	name, err := copyPath(containerPath)
	if err != nil {
		return err
	}
	root, err := openRunningRoot(c)
	if err != nil {
		return err
	}
	defer root.Close()
	src, err := os.OpenFile(hostPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("source must be a regular file: %s", hostPath)
	}
	dst, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	return copyRegular(dst, src, c.UID, c.GID)
}

func CopyFromContainer(c *Container, containerPath, hostPath string, uid, gid int) error {
	name, err := copyPath(containerPath)
	if err != nil {
		return err
	}
	root, err := openRunningRoot(c)
	if err != nil {
		return err
	}
	defer root.Close()
	src, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("source must be a regular file: %s", containerPath)
	}
	dst, err := os.OpenFile(hostPath, os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	return copyRegular(dst, src, uid, gid)
}

// The caller transfers ownership of dst to this function.
func copyRegular(dst, src *os.File, uid, gid int) (result error) {
	defer func() { result = errors.Join(result, dst.Close()) }()
	source, err := src.Stat()
	if err != nil {
		return err
	}
	target, err := dst.Stat()
	if err != nil {
		return err
	}
	if !source.Mode().IsRegular() || !target.Mode().IsRegular() {
		return fmt.Errorf("copy supports regular files only")
	}
	if os.SameFile(source, target) {
		return fmt.Errorf("source and destination are the same file")
	}
	if err := dst.Truncate(0); err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	if err := dst.Chown(uid, gid); err != nil {
		return err
	}
	if err := dst.Chmod(source.Mode().Perm()); err != nil {
		return err
	}
	return dst.Sync()
}
