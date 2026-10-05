package network

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

type Lease struct {
	Name  string        `json:"name"`
	IP    string        `json:"ip"`
	Token string        `json:"token"`
	Ports []PortMapping `json:"ports,omitempty"`
}

type IPAM struct{ Root string }

type allocationState struct {
	Subnet string           `json:"subnet"`
	Leases map[string]Lease `json:"leases"`
}

// Lock a separate, stable file: ipam.json itself is replaced atomically.
func (a IPAM) locked(fn func() error) error {
	if err := os.MkdirAll(a.Root, 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(a.Root, "network.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func (a IPAM) read() (*allocationState, error) {
	state := &allocationState{Subnet: Subnet, Leases: map[string]Lease{}}
	data, err := os.ReadFile(filepath.Join(a.Root, "ipam.json"))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("read IPAM state: %w", err)
	}
	if state.Subnet != Subnet || state.Leases == nil {
		return nil, fmt.Errorf("IPAM state does not match subnet %s", Subnet)
	}
	_, prefix, _ := net.ParseCIDR(Subnet)
	seen := map[string]bool{}
	for name, lease := range state.Leases {
		ip := net.ParseIP(lease.IP).To4()
		if ip == nil || !prefix.Contains(ip) || ip[3] < 2 || ip[3] == 255 ||
			lease.Name != name || lease.Token == "" || seen[lease.IP] {
			return nil, fmt.Errorf("invalid IPAM lease for %s", name)
		}
		seen[lease.IP] = true
	}
	return state, nil
}

func (a IPAM) write(state *allocationState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(a.Root, "ipam-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(append(data, '\n'))
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(a.Root, "ipam.json"))
}

func (a IPAM) Allocate(name string, ports []PortMapping) (Lease, error) {
	var chosen Lease
	err := a.locked(func() error {
		state, err := a.read()
		if err != nil {
			return err
		}
		if _, exists := state.Leases[name]; exists {
			return fmt.Errorf("container name %q already has a network lease", name)
		}
		usedIP, usedPort := map[string]bool{}, map[int]bool{}
		for _, lease := range state.Leases {
			usedIP[lease.IP] = true
			for _, port := range lease.Ports {
				usedPort[port.HostPort] = true
			}
		}
		for _, port := range ports {
			if port.HostPort < 1 || port.HostPort > 65535 || port.ContainerPort < 1 || port.ContainerPort > 65535 {
				return fmt.Errorf("ports must be between 1 and 65535")
			}
			if usedPort[port.HostPort] {
				return fmt.Errorf("host TCP port %d is already reserved", port.HostPort)
			}
			usedPort[port.HostPort] = true
		}
		// This lab deliberately allocates from one fixed /24.
		base, _, _ := net.ParseCIDR(Subnet)
		ip := base.To4()
		for last := 2; last < 255; last++ {
			ip[3] = byte(last)
			candidate := ip.String()
			if usedIP[candidate] {
				continue
			}
			token := make([]byte, 8)
			if _, err := rand.Read(token); err != nil {
				return err
			}
			chosen = Lease{name, candidate, hex.EncodeToString(token), append([]PortMapping(nil), ports...)}
			state.Leases[name] = chosen
			return a.write(state)
		}
		return fmt.Errorf("subnet %s has no free container addresses", Subnet)
	})
	if err != nil {
		return Lease{}, err
	}
	return chosen, nil
}

// Caller holds network.lock and has already removed the lease's resources.
func (a IPAM) releaseLocked(lease Lease) error {
	state, err := a.read()
	if err != nil {
		return err
	}
	current, exists := state.Leases[lease.Name]
	if !exists {
		return nil
	}
	if current.Token != lease.Token || current.IP != lease.IP {
		return fmt.Errorf("refusing to release a different lease for %s", lease.Name)
	}
	delete(state.Leases, lease.Name)
	return a.write(state)
}

func (a IPAM) Release(lease Lease) error {
	return a.locked(func() error { return a.releaseLocked(lease) })
}
