package image

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func archiveName(name string) (string, error) {
	if strings.HasPrefix(name, "/") || strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("unsafe archive path: %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("archive traversal: %q", name)
		}
	}
	return path.Clean(name), nil
}

// Every existing parent must be a real directory, never an archive symlink.
func layerDirectory(root, relative string, uid, gid int) error {
	current := root
	if relative == "." {
		return nil
	}
	for _, part := range strings.Split(relative, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0755); err != nil {
				return err
			}
			if err := os.Chown(current, uid, gid); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("archive parent is not a directory: %s", current)
		}
	}
	return nil
}

// Extract into a new, empty staging directory. Files use Lab 07's one-ID model.
// Whiteouts become OverlayFS metadata; lower layers are never edited.
func ExtractLayer(r io.Reader, target, wantDiffID string, uid, gid int) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	hash := sha256.New()
	// Bound expanded archive bytes, including padding and ignored headers.
	const maxExpanded = 512 << 20
	bounded := &io.LimitedReader{R: gz, N: maxExpanded + 1}
	plain := io.TeeReader(bounded, hash)
	tr := tar.NewReader(plain)
	type directory struct {
		mode     os.FileMode
		modified time.Time
	}
	dirs := map[string]directory{}
	hardlinks := map[string]string{}
	whiteouts := []string{}
	opaque := []string{}
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name, err := archiveName(h.Name)
		if err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("duplicate archive path: %s", name)
		}
		seen[name] = true
		if len(seen) > 100000 {
			return fmt.Errorf("layer has too many entries")
		}
		if name == "." && h.Typeflag != tar.TypeDir {
			return fmt.Errorf("archive root must be a directory")
		}
		if err := layerDirectory(target, path.Dir(name), uid, gid); err != nil {
			return err
		}
		base := path.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			if h.Typeflag != tar.TypeReg || h.Size != 0 {
				return fmt.Errorf("invalid whiteout: %s", name)
			}
			if base == ".wh..wh..opq" {
				opaque = append(opaque, path.Dir(name))
			} else {
				leaf := strings.TrimPrefix(base, ".wh.")
				if leaf == "" || leaf == "." || leaf == ".." {
					return fmt.Errorf("invalid whiteout name")
				}
				whiteouts = append(whiteouts, path.Join(path.Dir(name), leaf))
			}
			continue
		}
		full := filepath.Join(target, name)
		mode := os.FileMode(h.Mode & 0777)
		if h.Typeflag == tar.TypeDir && h.Mode&01000 != 0 {
			mode |= os.ModeSticky
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := layerDirectory(target, name, uid, gid); err != nil {
				return err
			}
			dirs[name] = directory{mode, h.ModTime}
		case tar.TypeReg:
			f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return err
			}
			if err := os.Chown(full, uid, gid); err != nil {
				return err
			}
			if err := os.Chmod(full, mode); err != nil {
				return err
			}
			if err := os.Chtimes(full, h.ModTime, h.ModTime); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.Symlink(h.Linkname, full); err != nil {
				return err
			}
			if err := os.Lchown(full, uid, gid); err != nil {
				return err
			}
		case tar.TypeLink:
			link, err := archiveName(h.Linkname)
			if err != nil {
				return err
			}
			hardlinks[name] = link
		default:
			return fmt.Errorf("unsupported tar entry type %d at %s", h.Typeflag, name)
		}
	}
	// tar EOF does not consume all tar padding or validate the gzip trailer.
	if _, err := io.Copy(io.Discard, plain); err != nil {
		return err
	}
	if bounded.N == 0 {
		return fmt.Errorf("expanded layer exceeds 512 MiB")
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != wantDiffID {
		return fmt.Errorf("uncompressed layer diff_id mismatch")
	}
	// Resolve forward hardlinks, but never link to a symlink or outside target.
	for len(hardlinks) != 0 {
		progress := false
		for name, link := range hardlinks {
			if _, pending := hardlinks[link]; pending {
				continue
			}
			if err := layerDirectory(target, path.Dir(link), uid, gid); err != nil {
				return err
			}
			info, err := os.Lstat(filepath.Join(target, link))
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("hardlink target is not a regular file: %s", link)
			}
			if err := os.Link(filepath.Join(target, link), filepath.Join(target, name)); err != nil {
				return err
			}
			delete(hardlinks, name)
			progress = true
		}
		if !progress {
			return fmt.Errorf("cyclic hardlink targets")
		}
	}
	for _, name := range whiteouts {
		hidden := false
		for _, dir := range opaque {
			if dir == "." || strings.HasPrefix(name, dir+"/") {
				hidden = true
				break
			}
		}
		if hidden {
			continue // an opaque ancestor already hides every lower entry here
		}
		full := filepath.Join(target, name)
		if _, err := os.Lstat(full); err == nil {
			continue // same-layer entry remains visible
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syscall.Mknod(full, syscall.S_IFCHR|0600, 0); err != nil {
			return fmt.Errorf("create OverlayFS whiteout %s: %w", name, err)
		}
	}
	for _, name := range opaque {
		if err := syscall.Setxattr(filepath.Join(target, name), "trusted.overlay.opaque", []byte("y"), 0); err != nil {
			return fmt.Errorf("set opaque directory %s: %w", name, err)
		}
	}
	// Apply directory modes last so restrictive modes cannot block extraction.
	names := make([]string, 0, len(dirs))
	for name := range dirs {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, name := range names {
		full, d := filepath.Join(target, name), dirs[name]
		if err := os.Chown(full, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(full, d.mode); err != nil {
			return err
		}
		if err := os.Chtimes(full, d.modified, d.modified); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) fetchLayer(c *Client, d Descriptor, diffID string) error {
	// Receipt and tree are committed together by renaming their parent directory.
	destination := filepath.Join(s.Root, "layers", d.Digest)
	receipt, err := os.ReadFile(filepath.Join(destination, "diff-id"))
	if err == nil {
		if strings.TrimSpace(string(receipt)) != diffID {
			return fmt.Errorf("cached layer diff_id mismatch")
		}
		info, err := os.Stat(filepath.Join(destination, "fs"))
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("cached layer has no filesystem")
		}
		fmt.Printf("Layer %s: cached\n", d.Digest)
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if d.Size > 256<<20 {
		return fmt.Errorf("compressed layer exceeds this lab's 256 MiB limit")
	}
	stage, err := os.MkdirTemp(filepath.Join(s.Root, "tmp"), "layer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	blob, err := os.Create(filepath.Join(stage, "blob.gz"))
	if err != nil {
		return err
	}
	defer blob.Close()
	r, err := c.BlobReader(d.Digest)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(blob, hash), io.LimitReader(r, d.Size+1))
	closeErr := r.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if n != d.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != d.Digest {
		return fmt.Errorf("compressed layer digest or size mismatch")
	}
	if _, err := blob.Seek(0, io.SeekStart); err != nil {
		return err
	}
	fs := filepath.Join(stage, "fs")
	if err := os.Mkdir(fs, 0755); err != nil {
		return err
	}
	if err := os.Chown(fs, s.UID, s.GID); err != nil {
		return err
	}
	if err := ExtractLayer(blob, fs, diffID, s.UID, s.GID); err != nil {
		return err
	}
	if err := blob.Close(); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(stage, "blob.gz")); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "diff-id"), []byte(diffID+"\n"), 0644); err != nil {
		return err
	}
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		return err
	}
	fmt.Printf("Layer %s: downloaded and extracted\n", d.Digest)
	return nil
}
