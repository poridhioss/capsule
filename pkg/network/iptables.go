package network

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

const (
	preChain  = "CAPSULE-PREROUTING"
	outChain  = "CAPSULE-OUTPUT"
	postChain = "CAPSULE-POSTROUTING"
	fwdChain  = "CAPSULE-FORWARD"
)

type PortMapping struct {
	HostPort      int `json:"host_port"`
	ContainerPort int `json:"container_port"`
}

func ParsePort(value string) (PortMapping, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return PortMapping{}, fmt.Errorf("invalid -p %q: use hostPort:containerPort (TCP/IPv4)", value)
	}
	host, err1 := strconv.Atoi(parts[0])
	container, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || host < 1 || host > 65535 || container < 1 || container > 65535 {
		return PortMapping{}, fmt.Errorf("both ports must be integers between 1 and 65535")
	}
	return PortMapping{host, container}, nil
}

type firewallRule struct {
	table, chain string
	args         []string
}

func newFirewall() (*iptables.IPTables, error) {
	return iptables.NewWithProtocol(iptables.ProtocolIPv4)
}

// Caller holds network.lock, serializing bridge and shared-rule creation.
func ensureFirewall(ipt *iptables.IPTables) error {
	for _, item := range []struct{ table, chain string }{
		{"nat", preChain}, {"nat", outChain}, {"nat", postChain}, {"filter", fwdChain},
	} {
		exists, err := ipt.ChainExists(item.table, item.chain)
		if err != nil {
			return err
		}
		if !exists {
			if err := ipt.NewChain(item.table, item.chain); err != nil {
				return err
			}
		}
	}
	shared := []firewallRule{
		{"nat", postChain, []string{"-s", Subnet, "!", "-o", BridgeName, "-j", "MASQUERADE"}},
		{"nat", postChain, []string{"-s", "127.0.0.0/8", "-d", Subnet, "-o", BridgeName, "-j", "MASQUERADE"}},
		{"filter", fwdChain, []string{"-i", BridgeName, "-o", BridgeName, "-s", Subnet, "-d", Subnet, "-j", "ACCEPT"}},
		{"filter", fwdChain, []string{"-i", BridgeName, "!", "-o", BridgeName, "-s", Subnet, "-j", "ACCEPT"}},
		{"filter", fwdChain, []string{"-o", BridgeName, "-d", Subnet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
	}
	for _, rule := range shared {
		if err := ipt.AppendUnique(rule.table, rule.chain, rule.args...); err != nil {
			return err
		}
	}
	// Scope DNAT to host-local destinations, not arbitrary transiting traffic.
	hooks := []firewallRule{
		{"nat", "PREROUTING", []string{"-m", "addrtype", "--dst-type", "LOCAL", "-j", preChain}},
		{"nat", "OUTPUT", []string{"-m", "addrtype", "--dst-type", "LOCAL", "-j", outChain}},
		{"nat", "POSTROUTING", []string{"-j", postChain}},
		{"filter", "FORWARD", []string{"-j", fwdChain}},
	}
	for _, rule := range hooks {
		if err := ipt.InsertUnique(rule.table, rule.chain, 1, rule.args...); err != nil {
			return err
		}
	}
	return nil
}

// Keep exact rule specifications so cleanup removes only this lease's rules.
func (c *Connection) publishPorts() error {
	for _, port := range c.Lease.Ports {
		host := strconv.Itoa(port.HostPort)
		container := strconv.Itoa(port.ContainerPort)
		comment := "capsule:" + c.Lease.Token
		dnat := []string{"-p", "tcp", "--dport", host, "-m", "comment", "--comment", comment,
			"-j", "DNAT", "--to-destination", c.Lease.IP + ":" + container}
		rules := []firewallRule{
			{"nat", preChain, dnat},
			{"nat", outChain, dnat},
			{"filter", fwdChain, []string{"-o", BridgeName, "-d", c.Lease.IP + "/32", "-p", "tcp", "--dport", container,
				"-m", "conntrack", "--ctstate", "DNAT", "--ctorigdstport", host,
				"-m", "comment", "--comment", comment, "-j", "ACCEPT"}},
			// Hairpin traffic must return through conntrack, even on this bridge.
			{"nat", postChain, []string{"-s", Subnet, "-d", c.Lease.IP + "/32", "-o", BridgeName,
				"-p", "tcp", "--dport", container, "-m", "conntrack", "--ctstate", "DNAT",
				"--ctorigdstport", host, "-m", "comment", "--comment", comment, "-j", "MASQUERADE"}},
		}
		for _, rule := range rules {
			if err := c.iptables.Append(rule.table, rule.chain, rule.args...); err != nil {
				return fmt.Errorf("publish TCP %s:%s: %w", host, container, err)
			}
			c.rules = append(c.rules, rule)
		}
	}
	return nil
}
