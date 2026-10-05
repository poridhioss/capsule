package filesystem

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const VolumeRoot = "/var/lib/capsule/volumes"

type MountKind int

const (
	MountBind MountKind = iota
	MountTmpfs
	MountNamed
)

type Mount struct {
	Kind             MountKind
	Source, Target   string
	ReadOnly         bool
	Size             int64  // tmpfs limit in bytes
	Mode             uint32 // tmpfs root permissions, including the sticky bit
	HostUID, HostGID int    // host IDs mapped to container UID/GID 0
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Names become directory components for both volumes and container layouts.
func ValidateName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("invalid name %q: use 1-64 letters, digits, dots, underscores or hyphens; start with a letter or digit", name)
	}
	return nil
}

func within(name, parent string) bool {
	if parent == "/" {
		return strings.HasPrefix(name, "/")
	}
	return name == parent || strings.HasPrefix(name, parent+"/")
}

func validateTarget(target string) error {
	if !path.IsAbs(target) || target == "/" || path.Clean(target) != target ||
		strings.ContainsAny(target, "\x00 \t\r\n") {
		return fmt.Errorf("target %q must be a clean absolute path other than /, without whitespace", target)
	}
	for _, reserved := range []string{"/proc", "/sys", "/dev", "/.old_root"} {
		if within(target, reserved) {
			return fmt.Errorf("target %q is reserved for runtime mounts", target)
		}
	}
	return nil
}

func ParseVolume(value string) (Mount, error) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" {
		return Mount{}, fmt.Errorf("invalid -v %q: expected source:/target[:ro|rw]", value)
	}
	m := Mount{Source: parts[0], Target: parts[1]}
	if err := validateTarget(m.Target); err != nil {
		return Mount{}, err
	}
	if filepath.IsAbs(m.Source) || strings.HasPrefix(m.Source, "./") ||
		strings.HasPrefix(m.Source, "../") || m.Source == "." || m.Source == ".." {
		m.Kind = MountBind
	} else {
		if err := ValidateName(m.Source); err != nil {
			return Mount{}, err
		}
		m.Kind = MountNamed
	}
	if len(parts) == 3 {
		switch parts[2] {
		case "ro":
			m.ReadOnly = true
		case "rw":
		default:
			return Mount{}, fmt.Errorf("invalid mount mode %q: use ro or rw", parts[2])
		}
	}
	return m, nil
}

func ParseTmpfs(value string) (Mount, error) {
	parts := strings.Split(value, ":")
	if len(parts) > 2 {
		return Mount{}, fmt.Errorf("invalid --tmpfs %q", value)
	}
	m := Mount{Kind: MountTmpfs, Target: parts[0], Size: 16 << 20, Mode: 01777}
	if err := validateTarget(m.Target); err != nil {
		return Mount{}, err
	}
	if len(parts) == 1 {
		return m, nil
	}
	seen := map[string]bool{}
	for _, option := range strings.Split(parts[1], ",") {
		key, value, ok := strings.Cut(option, "=")
		if !ok || seen[key] {
			return Mount{}, fmt.Errorf("invalid or repeated tmpfs option %q", option)
		}
		seen[key] = true
		switch key {
		case "size":
			size, err := parseSize(value)
			if err != nil {
				return Mount{}, err
			}
			m.Size = size
		case "mode":
			mode, err := strconv.ParseUint(value, 8, 32)
			if err != nil || len(value) > 4 || mode > 01777 {
				return Mount{}, fmt.Errorf("invalid tmpfs mode %q: use octal permissions up to 1777", value)
			}
			m.Mode = uint32(mode)
		default:
			return Mount{}, fmt.Errorf("unsupported tmpfs option %q", key)
		}
	}
	return m, nil
}

func parseSize(value string) (int64, error) {
	original := value
	value = strings.ToLower(value)
	factor := int64(1)
	if len(value) > 0 {
		switch value[len(value)-1] {
		case 'k':
			factor = 1 << 10
		case 'm':
			factor = 1 << 20
		case 'g':
			factor = 1 << 30
		}
		if factor != 1 {
			value = value[:len(value)-1]
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 || n > (1<<63-1)/factor {
		return 0, fmt.Errorf("invalid tmpfs size %q: use positive bytes or a k/m/g suffix", original)
	}
	return n * factor, nil
}

func ValidateMounts(mounts []Mount) error {
	for i, m := range mounts {
		if err := validateTarget(m.Target); err != nil {
			return err
		}
		for _, previous := range mounts[:i] {
			if within(m.Target, previous.Target) || within(previous.Target, m.Target) {
				return fmt.Errorf("overlapping mount targets %q and %q", previous.Target, m.Target)
			}
		}
	}
	return nil
}

// Existing volume data and ownership are preserved.
func CreateNamedVolume(name string, uid, gid int) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if err := os.MkdirAll(VolumeRoot, 0755); err != nil {
		return "", err
	}
	if _, err := ensureDirectory(VolumeRoot); err != nil {
		return "", err
	}
	dir := filepath.Join(VolumeRoot, name)
	created, err := ensureDirectory(dir)
	if err != nil {
		return "", err
	}
	if created {
		if err := os.Chown(dir, uid, gid); err != nil {
			_ = os.Remove(dir) // This invocation just created the empty directory.
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	owner := info.Sys().(*syscall.Stat_t)
	if int(owner.Uid) != uid || int(owner.Gid) != gid {
		return "", fmt.Errorf("volume %q belongs to %d:%d, not mapped user %d:%d", name, owner.Uid, owner.Gid, uid, gid)
	}
	return dir, nil
}

func ListVolumes() ([]string, error) {
	entries, err := os.ReadDir(VolumeRoot)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && namePattern.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	return names, nil // os.ReadDir returns entries sorted by name.
}

// Call only after all containers using this volume have exited.
func RemoveNamedVolume(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	dir := filepath.Join(VolumeRoot, name)
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("volume %q must be a real directory", name)
	}
	return os.RemoveAll(dir)
}

// Apply stages one mount before the child is created.
func Apply(rootfs string, m Mount) (result error) {
	var source string
	directory := true
	switch m.Kind {
	case MountNamed:
		var err error
		source, err = CreateNamedVolume(m.Source, m.HostUID, m.HostGID)
		if err != nil {
			return err
		}
	case MountBind:
		absolute, err := filepath.Abs(m.Source)
		if err != nil {
			return err
		}
		source, err = filepath.EvalSymlinks(absolute)
		if err != nil {
			return fmt.Errorf("bind source %q must exist: %w", m.Source, err)
		}
		info, err := os.Stat(source)
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("bind source must be a directory or regular file")
		}
		absoluteRoot, err := filepath.Abs(rootfs)
		if err != nil {
			return err
		}
		if within(absoluteRoot, source) {
			return fmt.Errorf("bind source %s contains the staged rootfs; choose a narrower source", source)
		}
		directory = info.IsDir()
	case MountTmpfs:
		if m.Size <= 0 {
			return fmt.Errorf("tmpfs size must be positive")
		}
	default:
		return fmt.Errorf("unknown mount kind %d", m.Kind)
	}
	target, err := prepareTarget(rootfs, m.Target, directory)
	if err != nil {
		return err
	}
	if m.Kind == MountTmpfs {
		options := fmt.Sprintf("size=%d,mode=%o,uid=%d,gid=%d", m.Size, m.Mode, m.HostUID, m.HostGID)
		if err := syscall.Mount("tmpfs", target, "tmpfs",
			syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, options); err != nil {
			return fmt.Errorf("mount tmpfs at %s: %w", m.Target, err)
		}
		return nil
	}
	if err := syscall.Mount(source, target, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s at %s: %w", source, m.Target, err)
	}
	// A failed propagation change or remount must undo this initial bind.
	defer func() {
		if result != nil {
			result = errors.Join(result, syscall.Unmount(target, syscall.MNT_DETACH))
		}
	}()
	if err := syscall.Mount("", target, "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("make bind private: %w", err)
	}
	return remountBindTree(target, m.ReadOnly)
}

// MS_REMOUNT|MS_BIND changes one mount at a time. Visit the complete copied
// subtree so a read-only recursive bind has no writable nested mount left.
func remountBindTree(target string, readOnly bool) error {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	optionFlags := map[string]uintptr{
		"ro": syscall.MS_RDONLY, "nosuid": syscall.MS_NOSUID,
		"nodev": syscall.MS_NODEV, "noexec": syscall.MS_NOEXEC,
		"noatime": syscall.MS_NOATIME, "nodiratime": syscall.MS_NODIRATIME,
		"relatime": syscall.MS_RELATIME, "strictatime": syscall.MS_STRICTATIME,
		"nosymfollow": 256, // Linux MS_NOSYMFOLLOW; absent from syscall's frozen constants.
	}
	flagsByPath := map[string]uintptr{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		name := unescape.Replace(fields[4])
		if !within(name, target) {
			continue
		}
		flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_NOSUID | syscall.MS_NODEV)
		for _, option := range strings.Split(fields[5], ",") {
			flags |= optionFlags[option]
		}
		if readOnly {
			flags |= syscall.MS_RDONLY
		}
		flagsByPath[name] = flags
	}
	if _, ok := flagsByPath[target]; !ok {
		return fmt.Errorf("bind target %s not found in mountinfo", target)
	}
	var paths []string
	for name := range flagsByPath {
		paths = append(paths, name)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, name := range paths {
		if err := syscall.Mount("", name, "", flagsByPath[name], ""); err != nil {
			return fmt.Errorf("remount %s: %w", name, err)
		}
	}
	return nil
}

func UnmountVolumes(rootfs string, mounts []Mount) error {
	var result error
	for i := len(mounts) - 1; i >= 0; i-- {
		target := filepath.Join(rootfs, strings.TrimPrefix(mounts[i].Target, "/"))
		if err := syscall.Unmount(target, syscall.MNT_DETACH); err != nil {
			result = errors.Join(result, fmt.Errorf("unmount %s: %w", target, err))
		}
	}
	return result
}

func ensureDirectory(dir string) (bool, error) {
	if err := os.Mkdir(dir, 0755); err == nil {
		return true, nil
	} else if !os.IsExist(err) {
		return false, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s must be a real directory, not a file or symlink", dir)
	}
	return false, nil
}

// Walk each destination component without following symlinks out of rootfs.
// Staging takes place in the trusted, idle lab tree before the child starts.
func prepareTarget(rootfs, target string, directory bool) (string, error) {
	if err := validateTarget(target); err != nil {
		return "", err
	}
	current, err := filepath.Abs(rootfs)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(current)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("rootfs must be a real directory")
	}
	parts := strings.Split(strings.TrimPrefix(target, "/"), "/")
	for i, part := range parts {
		current = filepath.Join(current, part)
		if i < len(parts)-1 || directory {
			if _, err := ensureDirectory(current); err != nil {
				return "", err
			}
			continue
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			file, err := os.OpenFile(current, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				return "", err
			}
			if err := file.Close(); err != nil {
				return "", err
			}
		} else if err != nil {
			return "", err
		} else if !info.Mode().IsRegular() {
			return "", fmt.Errorf("file target %s must be a regular file, not a directory or symlink", current)
		}
	}
	return current, nil
}
