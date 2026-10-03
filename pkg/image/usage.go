package image

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// The caller already holds the short, exclusive image-store lock.
func (s *Store) layerUseLock(mode int) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(s.Root, "images", ".usage-lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("image layers are in use by a running container")
	}
	return f, nil
}

// Multiple runs hold shared usage locks after image preparation finishes.
func PrepareForRun(root, value string, uid, gid int) (string, []string, *os.File, error) {
	s, err := OpenStore(root, uid, gid)
	if err != nil {
		return "", nil, nil, err
	}
	defer s.Close()
	id, lowers, err := s.Ensure(value)
	if err != nil {
		return "", nil, nil, err
	}
	use, err := s.layerUseLock(syscall.LOCK_SH)
	if err != nil {
		return "", nil, nil, err
	}
	return id, lowers, use, nil
}
