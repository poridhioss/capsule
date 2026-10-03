package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const StoreRoot = "/var/lib/capsule"

type Store struct {
	Root     string
	UID, GID int
	lock     *os.File
}

// Serialize image preparation and image-management commands.
func OpenStore(root string, uid, gid int) (*Store, error) {
	for _, part := range []string{"images/manifests", "images/configs", "images/tags", "layers", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, part), 0755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(filepath.Join(root, "images", ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("image store busy; retry after the other image operation finishes")
	}
	s := &Store{root, uid, gid, f}
	owner := filepath.Join(root, "images", "owner.json")
	want := struct{ UID, GID int }{uid, gid}
	data, err := os.ReadFile(owner)
	if errors.Is(err, os.ErrNotExist) {
		data, _ = json.Marshal(want)
		err = s.writeAtomic(owner, data)
	} else if err == nil {
		var have struct{ UID, GID int }
		err = json.Unmarshal(data, &have)
		if err == nil && have != want {
			err = fmt.Errorf("image store belongs to mapped UID:GID %d:%d; use the same sudo user", have.UID, have.GID)
		}
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.lock.Close() }

func (s *Store) writeAtomic(destination string, data []byte) error {
	f, err := os.CreateTemp(filepath.Join(s.Root, "tmp"), "metadata-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), 0644); err != nil {
		return err
	}
	return os.Rename(f.Name(), destination)
}

func (s *Store) readManifest(id string) (*Manifest, error) {
	if !validDigest(id) {
		return nil, fmt.Errorf("invalid stored manifest digest")
	}
	b, err := os.ReadFile(filepath.Join(s.Root, "images/manifests", id+".json"))
	if err != nil {
		return nil, err
	}
	if digest(b) != id {
		return nil, fmt.Errorf("stored manifest digest mismatch")
	}
	return parseManifest(b)
}

func (s *Store) Pull(value string) (string, error) {
	r, err := ParseReference(value)
	if err != nil {
		return "", err
	}
	c, err := NewClient(r.Repository)
	if err != nil {
		return "", err
	}
	m, raw, err := c.FetchManifest(r.Tag)
	if err != nil {
		return "", err
	}
	configBytes, err := c.ConfigBytes(m.Config)
	if err != nil {
		return "", err
	}
	config, err := parseConfig(configBytes, m)
	if err != nil {
		return "", err
	}
	for i, d := range m.Layers {
		if err := s.fetchLayer(c, d, config.RootFS.DiffIDs[i]); err != nil {
			return "", fmt.Errorf("layer %d: %w", i+1, err)
		}
	}
	id := digest(raw)
	if err := s.writeAtomic(filepath.Join(s.Root, "images/configs", m.Config.Digest+".json"), configBytes); err != nil {
		return "", err
	}
	if err := s.writeAtomic(filepath.Join(s.Root, "images/manifests", id+".json"), raw); err != nil {
		return "", err
	}
	// A tag becomes visible only after every referenced object is ready.
	if err := s.writeTag(r.String(), id); err != nil {
		return "", err
	}
	fmt.Printf("Pulled: %s\nDigest: %s\n", r.String(), id)
	return id, nil
}

func (s *Store) Ensure(value string) (string, []string, error) {
	id, err := s.Resolve(value)
	if errors.Is(err, os.ErrNotExist) {
		id, err = s.Pull(value)
	}
	if err != nil {
		return "", nil, err
	}
	m, err := s.readManifest(id)
	if err != nil {
		return "", nil, err
	}
	var lowers []string
	for i := len(m.Layers) - 1; i >= 0; i-- {
		dir := filepath.Join(s.Root, "layers", m.Layers[i].Digest, "fs")
		info, err := os.Stat(dir)
		if err != nil {
			return "", nil, err
		}
		if !info.IsDir() {
			return "", nil, fmt.Errorf("missing extracted layer: %s", dir)
		}
		lowers = append(lowers, dir)
	}
	return id, lowers, nil
}

// Prevent reuse of one writable layer over a different image's lower stack.
func PinContainer(base, id string) error {
	file := filepath.Join(base, "image-digest")
	old, err := os.ReadFile(file)
	if err == nil {
		if strings.TrimSpace(string(old)) != id {
			return fmt.Errorf("container writable layer belongs to another image; choose a new --name")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(base, "upper"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("existing upper has no image identity; use a fresh container name or preserve and move the old container directory")
	}
	if err := os.MkdirAll(base, 0755); err != nil {
		return err
	}
	return os.WriteFile(file, []byte(id+"\n"), 0644)
}
