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
		LinkAttrs: netlink.LinkAttrs{Name: HostIfName, Alias: connection.alias},
		PeerName:  PeerIfName,
	}
	if err := host.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("create veth pair: %w", err)
	}
	connection.created = true
	hostLink, err := host.LinkByName(HostIfName)
	if err != nil {
		return nil, err
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
