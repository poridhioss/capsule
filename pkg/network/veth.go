package network

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

const (
	HostIfName      = "cplhost0"
	PeerIfName      = "cplpeer0"
	ContainerIfName = "eth0"
	Subnet          = "172.30.50.0/30"
	HostCIDR        = "172.30.50.1/30"
	ContainerCIDR   = "172.30.50.2/30"
	HostIP          = "172.30.50.1"
	ContainerIP     = "172.30.50.2"
)

type Connection struct {
	host    *netlink.Handle
	child   *ChildNamespace
	alias   string
	created bool
}

// Refuse collisions instead of replacing host interfaces or routes.
func checkHost(host *netlink.Handle) error {
	for _, name := range []string{HostIfName, PeerIfName} {
		_, err := host.LinkByName(name)
		if err == nil {
			return fmt.Errorf("host interface %s already exists", name)
		}
		var missing netlink.LinkNotFoundError
		if !errors.As(err, &missing) {
			return fmt.Errorf("inspect host interface %s: %w", name, err)
		}
	}
	_, subnet, err := net.ParseCIDR(Subnet)
	if err != nil {
		return err
	}
	routes, err := host.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list host IPv4 routes: %w", err)
	}
	for _, route := range routes {
		if route.Dst == nil {
			continue // The existing default route must remain in place.
		}
		bits, _ := route.Dst.Mask.Size()
		if bits == 0 {
			continue
		}
		if route.Dst.Contains(subnet.IP) || subnet.Contains(route.Dst.IP) {
			return fmt.Errorf("lab subnet %s overlaps host route %s", Subnet, route.Dst)
		}
	}
	return nil
}

func assignIP(handle *netlink.Handle, link netlink.Link, cidr string) error {
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if err := handle.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("assign %s to %s: %w", cidr, link.Attrs().Name, err)
	}
	if err := handle.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", link.Attrs().Name, err)
	}
	return nil
}

// The child must remain behind its start gate until Setup returns.
func Setup(childPID int) (_ *Connection, result error) {
	host, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open host netlink handle: %w", err)
	}
	connection := &Connection{host: host, alias: fmt.Sprintf("capsule:%d", childPID)}
	defer func() {
		if result != nil {
			result = errors.Join(result, connection.Cleanup())
		}
	}()
	if err := checkHost(host); err != nil {
		return nil, err
	}
	child, err := OpenChildNamespace(childPID)
	if err != nil {
		return nil, err
	}
	// Keep the namespace alive until veth cleanup has finished.
	connection.child = child

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: HostIfName},
		PeerName:  PeerIfName,
	}
	if err := host.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("create veth pair: %w", err)
	}
	// LinkAdd records the new host endpoint's interface index.
	createdIndex := veth.Attrs().Index
	if createdIndex <= 0 {
		return nil, fmt.Errorf("created veth has no interface index; inspect %s before retrying", HostIfName)
	}
	// Setup can fail before the alias is established. Roll back only the
	// pair created above, using its saved index rather than a name lookup.
	// This defer runs before Cleanup closes the namespace and handles.
	defer func() {
		if result == nil {
			return
		}
		created := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: createdIndex}}
		if err := host.LinkDel(created); err != nil && !errors.Is(err, syscall.ENODEV) {
			result = errors.Join(result, fmt.Errorf("roll back new veth pair: %w", err))
		}
	}()

	hostLink, err := host.LinkByIndex(createdIndex)
	if err != nil {
		return nil, fmt.Errorf("find new host veth: %w", err)
	}
	peer, err := host.LinkByName(PeerIfName)
	if err != nil {
		return nil, err
	}
	if err := host.LinkSetNsFd(peer, int(child.FD)); err != nil {
		return nil, fmt.Errorf("move veth peer to child: %w", err)
	}

	// Look up the moved interface again, using the child's routing socket.
	peer, err = child.Handle.LinkByName(PeerIfName)
	if err != nil {
		return nil, err
	}
	if err := child.Handle.LinkSetName(peer, ContainerIfName); err != nil {
		return nil, fmt.Errorf("rename child interface: %w", err)
	}
	peer, err = child.Handle.LinkByName(ContainerIfName)
	if err != nil {
		return nil, err
	}
	loopback, err := child.Handle.LinkByName("lo")
	if err != nil {
		return nil, err
	}
	if err := child.Handle.LinkSetUp(loopback); err != nil {
		return nil, fmt.Errorf("bring up child loopback: %w", err)
	}
	if err := assignIP(host, hostLink, HostCIDR); err != nil {
		return nil, err
	}
	if err := assignIP(child.Handle, peer, ContainerCIDR); err != nil {
		return nil, err
	}
	if err := child.Handle.RouteAdd(&netlink.Route{
		LinkIndex: peer.Attrs().Index,
		Gw:        net.ParseIP(HostIP),
	}); err != nil {
		return nil, fmt.Errorf("add child default route: %w", err)
	}
	// Set the ownership marker after configuring the pair, then verify
	// the kernel's value before releasing the child to run its workload.
	if err := host.LinkSetAlias(hostLink, connection.alias); err != nil {
		return nil, fmt.Errorf("set host veth alias: %w", err)
	}
	hostLink, err = host.LinkByIndex(createdIndex)
	if err != nil {
		return nil, fmt.Errorf("read back host veth alias: %w", err)
	}
	if hostLink.Type() != "veth" || hostLink.Attrs().Alias != connection.alias {
		return nil, fmt.Errorf(
			"verify host veth ownership: type=%q alias=%q; expected type=\"veth\" alias=%q",
			hostLink.Type(), hostLink.Attrs().Alias, connection.alias,
		)
	}
	// Normal cleanup may now require the verified type and alias.
	connection.created = true
	return connection, nil
}

func (connection *Connection) Cleanup() error {
	if connection == nil {
		return nil
	}

	host := connection.host
	defer func() {
		// Release the namespace only after the link cleanup attempt.
		if connection.child != nil {
			connection.child.Close()
			connection.child = nil
		}
		if host != nil {
			host.Close()
			connection.host = nil
		}
	}()

	if host == nil || !connection.created {
		return nil
	}

	link, err := host.LinkByName(HostIfName)
	var missing netlink.LinkNotFoundError
	if errors.As(err, &missing) || errors.Is(err, syscall.ENODEV) {
		connection.created = false
		return nil
	}
	if err != nil {
		return fmt.Errorf("find veth for cleanup: %w", err)
	}

	if link.Type() != "veth" || link.Attrs().Alias != connection.alias {
		return fmt.Errorf(
			"refusing to delete %s: type=%q alias=%q; expected type=\"veth\" alias=%q",
			HostIfName, link.Type(), link.Attrs().Alias, connection.alias,
		)
	}

	if err := host.LinkDel(link); err != nil && !errors.Is(err, syscall.ENODEV) {
		return fmt.Errorf("delete veth pair: %w", err)
	}

	connection.created = false
	return nil
}
