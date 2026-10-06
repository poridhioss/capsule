package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type Tag struct{ Name, Digest string }

func (s *Store) tagPath(name string) string {
	return filepath.Join(s.Root, "images/tags", strings.TrimPrefix(digest([]byte(name)), "sha256:")+".json")
}

func (s *Store) writeTag(name, id string) error {
	data, err := json.Marshal(Tag{name, id})
	if err != nil {
		return err
	}
	return s.writeAtomic(s.tagPath(name), data)
}

func (s *Store) Resolve(value string) (string, error) {
	r, err := ParseReference(value)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(s.tagPath(r.String()))
	if err != nil {
		return "", err
	}
	var t Tag
	if err := json.Unmarshal(data, &t); err != nil {
		return "", err
	}
	if t.Name != r.String() || !validDigest(t.Digest) {
		return "", fmt.Errorf("invalid stored tag")
	}
	return t.Digest, nil
}

func (s *Store) Tags() ([]Tag, error) {
	files, err := os.ReadDir(filepath.Join(s.Root, "images/tags"))
	if err != nil {
		return nil, err
	}
	var tags []Tag
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.Root, "images/tags", f.Name()))
		if err != nil {
			return nil, err
		}
		var t Tag
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, err
		}
		r, err := ParseReference(t.Name)
		if err != nil || r.String() != t.Name || !validDigest(t.Digest) || filepath.Base(s.tagPath(t.Name)) != f.Name() {
			return nil, fmt.Errorf("invalid tag record: %s", f.Name())
		}
		tags = append(tags, t)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i].Name < tags[j].Name })
	return tags, nil
}

func (s *Store) List() error {
	tags, err := s.Tags()
	if err != nil {
		return err
	}
	fmt.Println("IMAGE\tMANIFEST\tCOMPRESSED SIZE")
	for _, t := range tags {
		m, err := s.readManifest(t.Digest)
		if err != nil {
			return err
		}
		var bytes int64
		seen := map[string]bool{}
		for _, d := range m.Layers {
			if !seen[d.Digest] {
				bytes += d.Size
				seen[d.Digest] = true
			}
		}
		fmt.Printf("%s\t%s\t%d bytes\n", t.Name, t.Digest, bytes)
	}
	return nil
}

func (s *Store) Tag(source, target string) error {
	id, err := s.Resolve(source)
	if err != nil {
		return err
	}
	if _, err := s.readManifest(id); err != nil {
		return err
	}
	r, err := ParseReference(target)
	if err != nil {
		return err
	}
	if err := s.writeTag(r.String(), id); err != nil {
		return err
	}
	fmt.Printf("Tagged: %s -> %s\n", r.String(), id)
	return nil
}

// Recompute counts from committed tags; there is no mutable counter database.
func (s *Store) references(skip string) (map[string]int, map[string]int, map[string]int, error) {
	tags, err := s.Tags()
	if err != nil {
		return nil, nil, nil, err
	}
	manifests, layers, configs := map[string]int{}, map[string]int{}, map[string]int{}
	for _, t := range tags {
		m, err := s.readManifest(t.Digest)
		if err != nil {
			return nil, nil, nil, err
		}
		if t.Name == skip {
			continue
		}
		manifests[t.Digest]++
		configs[m.Config.Digest]++
		unique := map[string]bool{}
		for _, d := range m.Layers {
			if !unique[d.Digest] {
				layers[d.Digest]++
				unique[d.Digest] = true
			}
		}
	}
	return manifests, layers, configs, nil
}

func (s *Store) Remove(value string) error {
	unused, err := s.layerUseLock(syscall.LOCK_EX)
	if err != nil {
		return err
	}
	defer unused.Close()
	r, err := ParseReference(value)
	if err != nil {
		return err
	}
	if _, err := s.Resolve(value); err != nil {
		return err
	}
	manifests, layers, configs, err := s.references(r.String())
	if err != nil {
		return err
	}
	if err := os.Remove(s.tagPath(r.String())); err != nil {
		return err
	}
	fmt.Printf("Untagged: %s\n", r.String())
	for _, group := range []struct {
		path, suffix string
		refs         map[string]int
	}{
		{"images/manifests", ".json", manifests}, {"images/configs", ".json", configs}, {"layers", "", layers},
	} {
		entries, err := os.ReadDir(filepath.Join(s.Root, group.path))
		if err != nil {
			return err
		}
		for _, entry := range entries {
			id := strings.TrimSuffix(entry.Name(), group.suffix)
			if !validDigest(id) || group.refs[id] != 0 {
				continue
			}
			if err := os.RemoveAll(filepath.Join(s.Root, group.path, entry.Name())); err != nil {
				return err
			}
			if group.path == "layers" {
				fmt.Printf("Removed layer: %s\n", id)
			}
		}
	}
	return nil
}

// Minimal dispatch for this lab; the full CLI arrives in the CLI lab.
func Command(args []string, uid, gid int) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run capsule with sudo")
	}
	want := map[string]int{"pull": 2, "images": 1, "tag": 3, "rmi": 2}
	if len(args) == 0 || want[args[0]] != len(args) {
		return fmt.Errorf("usage: capsule pull IMAGE | images | tag SOURCE TARGET | rmi IMAGE")
	}
	s, err := OpenStore(StoreRoot, uid, gid)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "pull":
		_, err = s.Pull(args[1])
	case "images":
		err = s.List()
	case "tag":
		err = s.Tag(args[1], args[2])
	case "rmi":
		err = s.Remove(args[1])
	}
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("image is not stored locally: %w", err)
	}
	return err
}
