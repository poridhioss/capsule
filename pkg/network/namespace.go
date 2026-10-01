package network

import (
	"fmt"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// A namespace FD identifies the destination for LinkSetNsFd. The handle's
// routing socket sends subsequent requests to that namespace.
type ChildNamespace struct {
	FD     netns.NsHandle
	Handle *netlink.Handle
}

func OpenChildNamespace(pid int) (*ChildNamespace, error) {
	fd, err := netns.GetFromPid(pid)
	if err != nil {
		return nil, fmt.Errorf("open child network namespace: %w", err)
	}
	current, err := netns.Get()
	if err != nil {
		_ = fd.Close()
		return nil, err
	}
	same := fd.Equal(current)
	_ = current.Close()
	if same {
		_ = fd.Close()
		return nil, fmt.Errorf("child shares the parent's network namespace; enable Net: true")
	}

	handle, err := netlink.NewHandleAt(fd, syscall.NETLINK_ROUTE)
	if err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("open child netlink handle: %w", err)
	}
	return &ChildNamespace{FD: fd, Handle: handle}, nil
}

func (ns *ChildNamespace) Close() {
	ns.Handle.Close()
	_ = ns.FD.Close()
}

func NamespaceID(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
}
