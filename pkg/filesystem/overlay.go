package filesystem

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// OverlayConfig describes a single OverlayFS mount: one or more read-only lower
// directories, a writable upper directory, a work directory for kernel
// bookkeeping, and the merged mount point that the container will see as its
// rootfs.
type OverlayConfig struct {
	LowerDirs []string // read-only base layers, highest-priority first
	UpperDir  string   // writable layer for this container's changes
	WorkDir   string   // kernel scratch space, must be empty and on UpperDir's fs
	MergedDir string   // mount point, becomes the container rootfs
}

// MountOverlay creates UpperDir, WorkDir, and MergedDir if they do not exist,
// then mounts an overlay at MergedDir. The LowerDirs slice must be non-empty;
// the leftmost entry is the highest-priority layer.
func MountOverlay(c OverlayConfig) error {
	if len(c.LowerDirs) == 0 {
		return fmt.Errorf("overlay: at least one lowerdir is required")
	}
	for _, d := range []string{c.UpperDir, c.WorkDir, c.MergedDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("overlay: mkdir %s: %w", d, err)
		}
	}
	// Digest directory names contain a literal colon. Escape it inside each
	// pathname before joining paths with the lowerdir separator.
	escaped := make([]string, len(c.LowerDirs))
	for i, dir := range c.LowerDirs {
		if strings.ContainsAny(dir, ",\\\n") {
			return fmt.Errorf("unsupported character in lowerdir path")
		}
		escaped[i] = strings.ReplaceAll(dir, ":", `\:`)
	}
	for _, dir := range []string{c.UpperDir, c.WorkDir, c.MergedDir} {
		if strings.ContainsAny(dir, ",\\\n") {
			return fmt.Errorf("unsupported character in overlay path")
		}
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		strings.Join(escaped, ":"), c.UpperDir, c.WorkDir)
	if len(opts) >= os.Getpagesize() {
		return fmt.Errorf("overlay mount options exceed one page; use an image with fewer layers")
	}
	if err := syscall.Mount("overlay", c.MergedDir, "overlay", 0, opts); err != nil {
		return fmt.Errorf("overlay: mount %s: %w", c.MergedDir, err)
	}
	return nil
}

// UnmountOverlay tears down the overlay mounted at merged. MNT_DETACH lets the
// unmount succeed even if a process inside the container still holds a
// reference; the actual unmount happens when the last reference goes away.
func UnmountOverlay(merged string) error {
	if err := syscall.Unmount(merged, syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("overlay: unmount %s: %w", merged, err)
	}
	return nil
}
