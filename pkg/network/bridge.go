package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
)

const (
	StateRoot       = "/var/lib/capsule"
	BridgeName      = "capsule0"
	BridgeAlias     = "capsule:lab12-bridge"
	Subnet          = "172.18.0.0/24"
	GatewayCIDR     = "172.18.0.1/24"
	GatewayIP       = "172.18.0.1"
	ContainerIfName = "eth0"
)

func ensureBridge(host *netlink.Handle) (_ netlink.Link, result error) {
	bridge, err := host.LinkByName(BridgeName)
	var missing netlink.LinkNotFoundError
	if err != nil && !errors.As(err, &missing) {
		return nil, err
	}
	if err == nil && (bridge.Type() != "bridge" || bridge.Attrs().Alias != BridgeAlias) {
		return nil, fmt.Errorf("%s exists but is not Capsule's bridge", BridgeName)
	}

	_, prefix, _ := net.ParseCIDR(Subnet)
	routes, err := host.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route.Dst == nil || (bridge != nil && route.LinkIndex == bridge.Attrs().Index) {
			continue
		}
		bits, _ := route.Dst.Mask.Size()
		if bits != 0 && (route.Dst.Contains(prefix.IP) || prefix.Contains(route.Dst.IP)) {
			return nil, fmt.Errorf("bridge subnet %s overlaps host route %s", Subnet, route.Dst)
		}
	}
	createdIndex := 0
	if bridge == nil {
		bridge = &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: BridgeName}}
		if err := host.LinkAdd(bridge); err != nil {
			return nil, fmt.Errorf("create bridge: %w", err)
		}
		createdIndex = bridge.Attrs().Index
		if createdIndex <= 0 {
			return nil, fmt.Errorf("created bridge has no interface index; inspect %s before retrying", BridgeName)
		}
		// Roll back only a bridge created by this call. Its alias may not
		// have been set yet; an existing shared bridge must never be deleted.
		defer func() {
			if result != nil {
				created := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Index: createdIndex}}
				if err := host.LinkDel(created); err != nil && !errors.Is(err, syscall.ENODEV) {
					result = errors.Join(result, fmt.Errorf("roll back new bridge: %w", err))
				}
			}
		}()
		bridge, err = host.LinkByIndex(createdIndex)
		if err != nil {
			return nil, err
		}
	}
	addresses, err := host.AddrList(bridge, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		address, _ := netlink.ParseAddr(GatewayCIDR)
		if err := host.AddrAdd(bridge, address); err != nil {
			return nil, err
		}
	} else if len(addresses) != 1 || addresses[0].IPNet.String() != GatewayCIDR {
		return nil, fmt.Errorf("bridge %s has unexpected IPv4 addresses", BridgeName)
	}
	if err := host.LinkSetUp(bridge); err != nil {
		return nil, err
	}

	// Changing ip_forward can reset other IP settings: enable it first.
	forward, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(forward)) != "1" {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
			return nil, fmt.Errorf("enable IPv4 forwarding: %w", err)
		}
	}
	// Needed for host 127.0.0.1 -> OUTPUT DNAT -> bridge traffic.
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+BridgeName+"/route_localnet", []byte("1\n"), 0644); err != nil {
		return nil, fmt.Errorf("enable bridge loopback routing: %w", err)
	}
	if createdIndex > 0 {
		// Set and read back the marker after configuration. Do not retag
		// an existing interface whose ownership check failed above.
		if err := host.LinkSetAlias(bridge, BridgeAlias); err != nil {
			return nil, fmt.Errorf("set bridge alias: %w", err)
		}
		bridge, err = host.LinkByIndex(createdIndex)
		if err != nil {
			return nil, fmt.Errorf("read back bridge alias: %w", err)
		}
		if bridge.Type() != "bridge" || bridge.Attrs().Alias != BridgeAlias {
			return nil, fmt.Errorf(
				"verify bridge ownership: type=%q alias=%q; expected type=\"bridge\" alias=%q",
				bridge.Type(), bridge.Attrs().Alias, BridgeAlias,
			)
		}
	}
	return bridge, nil
}

func assignIP(handle *netlink.Handle, link netlink.Link, cidr string) error {
	address, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if err := handle.AddrAdd(link, address); err != nil {
		return fmt.Errorf("assign %s: %w", cidr, err)
	}
	return handle.LinkSetUp(link)
}
