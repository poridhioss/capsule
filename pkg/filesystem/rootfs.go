package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// PivotRoot swaps the calling process's root filesystem to rootfs.
// It must be called from inside a mount namespace (CLONE_NEWNS).
//
// Steps:
//   1. Bind-mount rootfs onto itself so it qualifies as a mount point.
//   2. Create rootfs/.old_root as the holding location for the old root.
//   3. Call pivot_root(rootfs, rootfs/.old_root).
//   4. Chdir to "/" so the working directory follows the new root.
//   5. Unmount /.old_root with MNT_DETACH and remove the empty directory.
func PivotRoot(rootfs string) error {
	// 1. Bind-mount rootfs onto itself so pivot_root accepts it.
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mount rootfs: %w", err)
	}

	// 2. Create the directory that will hold the old root.
	oldRoot := filepath.Join(rootfs, ".old_root")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return fmt.Errorf("mkdir old_root: %w", err)
	}

	// 3. Pivot: rootfs becomes /, old root moves to /.old_root.
	if err := syscall.PivotRoot(rootfs, oldRoot); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}

	// 4. Move into the new root.
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}

	// 5. Detach the old root and remove the mount point directory.
	if err := syscall.Unmount("/.old_root", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount old_root: %w", err)
	}
	if err := os.Remove("/.old_root"); err != nil {
		return fmt.Errorf("remove old_root: %w", err)
	}

	return nil
}