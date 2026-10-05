package container

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/poridhioss/capsule/pkg/filesystem"
)

const Root = "/var/lib/capsule/containers"
const lockRoot = "/var/lib/capsule/container-locks"

// The lock lives outside the metadata directory, so removal cannot replace it.
func lockContainer(id string) (*os.File, error) {
	if err := filesystem.ValidateName(id); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(lockRoot, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(lockRoot, id+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("container %s has an active operation: %w", id, err)
	}
	return f, nil
}

// All writers hold the container lock. Readers see either complete version.
func (c *Container) Persist() error {
	dir := filepath.Join(Root, c.ID)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "config-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, "config.json"))
}

func Load(id string) (*Container, error) {
	if err := filesystem.ValidateName(id); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(Root, id, "config.json"))
	if err != nil {
		return nil, err
	}
	var c Container
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.ID != id || c.Name != id || !filepath.IsAbs(c.Base) || filepath.Clean(c.Base) != c.Base ||
		filepath.Base(c.Base) != id || filepath.Base(filepath.Dir(c.Base)) != "containers" {
		return nil, fmt.Errorf("invalid container metadata for %s", id)
	}
	return &c, nil
}

func List() ([]*Container, error) {
	entries, err := os.ReadDir(Root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result []*Container
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, err := Load(entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue // A concurrent create/remove may not have a config file yet.
		}
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
