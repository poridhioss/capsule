package namespace

import (
	"os/exec"
	"syscall"
)

// Config describes the namespaces a child process should be cloned into,
// plus any UID/GID mappings and ambient capabilities required when a user
// namespace is requested.
type Config struct {
	PID, UTS, Mount bool
	Net, User       bool
	Hostname        string
	UIDMap, GIDMap  []syscall.SysProcIDMap
	AmbientCaps     []uintptr
}

// Cloneflags returns the flag word for clone() that requests the namespaces
// described by c. A zero Config returns 0.
func (c Config) Cloneflags() uintptr {
	var f uintptr
	if c.PID {
		f |= syscall.CLONE_NEWPID
	}
	if c.UTS {
		f |= syscall.CLONE_NEWUTS
	}
	if c.Mount {
		f |= syscall.CLONE_NEWNS
	}
	if c.Net {
		f |= syscall.CLONE_NEWNET
	}
	if c.User {
		f |= syscall.CLONE_NEWUSER
	}
	return f
}

// Apply attaches a SysProcAttr to cmd that requests the namespaces, mappings,
// and ambient capabilities described by c. Call this before cmd.Start().
func (c Config) Apply(cmd *exec.Cmd) {
	sp := &syscall.SysProcAttr{Cloneflags: c.Cloneflags()}
	if c.User {
		sp.UidMappings = c.UIDMap
		sp.GidMappings = c.GIDMap
		// Write "deny" to /proc/PID/setgroups before gid_map. Closes the
		// setgroups escalation in user namespaces.
		sp.GidMappingsEnableSetgroups = false
	}
	if len(c.AmbientCaps) > 0 {
		sp.AmbientCaps = c.AmbientCaps
	}
	cmd.SysProcAttr = sp
}
