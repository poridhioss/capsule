package network

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

type Connection struct {
	Lease         Lease
	HostIfName    string
	ipam          IPAM
	host          *netlink.Handle
	child         *ChildNamespace
	hostIndex     int
	iptables      *iptables.IPTables
	rules         []firewallRule
	listeners     []net.Listener
	created       bool
	aliasVerified bool
	closed        bool
}

// Reserve the name/IP before touching that container's upper layer or cgroup.
func Reserve(name string, ports []PortMapping) (*Connection, error) {
	a := IPAM{Root: StateRoot}
	lease, err := a.Allocate(name, ports)
	if err != nil {
		return nil, err
	}
	c := &Connection{Lease: lease, ipam: a}
	for _, port := range ports {
		listener, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port.HostPort))
		if err != nil {
			return nil, errors.Join(fmt.Errorf("reserve host TCP port %d: %w", port.HostPort, err), c.Cleanup())
		}
		// These sockets reserve ports; DNAT, not an application proxy, carries traffic.
		c.listeners = append(c.listeners, listener)
	}
	return c, nil
}

// The caller keeps the child behind FD 3 until this method succeeds.
func (c *Connection) Setup(childPID int) error {
	return c.ipam.locked(func() error {
		var err error
		c.host, err = netlink.NewHandle(syscall.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		bridge, err := ensureBridge(c.host)
		if err != nil {
			return err
		}
		c.iptables, err = newFirewall()
		if err != nil {
			return err
		}
		if err := ensureFirewall(c.iptables); err != nil {
			return err
		}
		child, err := OpenChildNamespace(childPID)
		if err != nil {
			return err
		}
		// Keep the child's namespace alive until the veth cleanup attempt.
		c.child = child

		c.HostIfName = fmt.Sprintf("cplv%d", childPID)
		peerName := fmt.Sprintf("cplp%d", childPID)
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: c.HostIfName},
			PeerName:  peerName,
		}
		if err := c.host.LinkAdd(veth); err != nil {
			return fmt.Errorf("create veth: %w", err)
		}
		c.created = true
		// Remember the new endpoint for both normal cleanup and rollback
		// if setup fails before the ownership marker is verified.
		c.hostIndex = veth.Attrs().Index
		if c.hostIndex <= 0 {
			return fmt.Errorf("created veth has no interface index; inspect %s before retrying", c.HostIfName)
		}
		hostLink, err := c.host.LinkByIndex(c.hostIndex)
		if err != nil {
			return err
		}
		peer, err := c.host.LinkByName(peerName)
		if err != nil {
			return err
		}
		if err := c.host.LinkSetNsFd(peer, int(child.FD)); err != nil {
			return err
		}
		if err := c.host.LinkSetMaster(hostLink, bridge); err != nil {
			return err
		}
		if err := c.host.LinkSetHairpin(hostLink, true); err != nil {
			return err
		}
		if err := c.host.LinkSetUp(hostLink); err != nil {
			return err
		}
		peer, err = child.Handle.LinkByName(peerName)
		if err != nil {
			return err
		}
		if err := child.Handle.LinkSetName(peer, ContainerIfName); err != nil {
			return err
		}
		peer, err = child.Handle.LinkByName(ContainerIfName)
		if err != nil {
			return err
		}
		loopback, err := child.Handle.LinkByName("lo")
		if err != nil {
			return err
		}
		if err := child.Handle.LinkSetUp(loopback); err != nil {
			return err
		}
		if err := assignIP(child.Handle, peer, c.Lease.IP+"/24"); err != nil {
			return err
		}
		if err := child.Handle.RouteAdd(&netlink.Route{LinkIndex: peer.Attrs().Index, Gw: net.ParseIP(GatewayIP)}); err != nil {
			return err
		}
		// Carry forward Lab 11's explicit alias write and kernel read-back.
		// Lab 12 uses the lease token to distinguish concurrent connections.
		expectedAlias := "capsule:" + c.Lease.Token
		if err := c.host.LinkSetAlias(hostLink, expectedAlias); err != nil {
			return fmt.Errorf("set host veth alias: %w", err)
		}
		hostLink, err = c.host.LinkByIndex(c.hostIndex)
		if err != nil {
			return fmt.Errorf("read back host veth alias: %w", err)
		}
		if hostLink.Type() != "veth" || hostLink.Attrs().Alias != expectedAlias {
			return fmt.Errorf(
				"verify host veth ownership: type=%q alias=%q; expected type=\"veth\" alias=%q",
				hostLink.Type(), hostLink.Attrs().Alias, expectedAlias,
			)
		}
		c.aliasVerified = true
		return c.publishPorts()
	})
}

func (c *Connection) removePair() error {
	if !c.created || c.host == nil {
		return nil
	}
	if c.hostIndex <= 0 {
		return fmt.Errorf("refusing to delete %s without its recorded interface index", c.HostIfName)
	}
	link, err := c.host.LinkByIndex(c.hostIndex)
	var missing netlink.LinkNotFoundError
	if errors.As(err, &missing) || errors.Is(err, syscall.ENODEV) {
		c.created = false
		return nil
	}
	if err != nil {
		return fmt.Errorf("find veth for cleanup: %w", err)
	}
	if link.Type() != "veth" || link.Attrs().Name != c.HostIfName {
		return fmt.Errorf("refusing to delete interface index %d: type=%q name=%q; expected veth %q",
			c.hostIndex, link.Type(), link.Attrs().Name, c.HostIfName)
	}
	// Before verification, this is rollback of the pair created by Setup.
	// After verification, normal cleanup must also match the lease alias.
	expectedAlias := "capsule:" + c.Lease.Token
	if c.aliasVerified && link.Attrs().Alias != expectedAlias {
		return fmt.Errorf(
			"refusing to delete %s: type=%q alias=%q; expected type=\"veth\" alias=%q",
			c.HostIfName, link.Type(), link.Attrs().Alias, expectedAlias,
		)
	}
	if err := c.host.LinkDel(link); err != nil && !errors.Is(err, syscall.ENODEV) {
		return fmt.Errorf("delete veth pair: %w", err)
	}
	c.created = false
	return nil
}

func (c *Connection) Cleanup() error {
	if c == nil || c.closed {
		return nil
	}
	err := c.ipam.locked(func() error {
		var cleanupErr error
		for i := len(c.rules) - 1; i >= 0; i-- {
			rule := c.rules[i]
			cleanupErr = errors.Join(cleanupErr, c.iptables.DeleteIfExists(rule.table, rule.chain, rule.args...))
		}
		cleanupErr = errors.Join(cleanupErr, c.removePair())
		if cleanupErr != nil {
			// A stale DNAT target must not be reassigned to another container.
			return fmt.Errorf("network cleanup failed; retaining IPAM lease: %w", cleanupErr)
		}
		return c.ipam.releaseLocked(c.Lease)
	})
	for _, listener := range c.listeners {
		_ = listener.Close()
	}
	// Release namespace references only after the link cleanup attempt.
	if c.child != nil {
		c.child.Close()
		c.child = nil
	}
	if c.host != nil {
		c.host.Close()
		c.host = nil
	}
	c.closed = true
	return err
}
