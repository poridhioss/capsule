package namespace

import "syscall"

// DefaultMapping returns UID and GID mapping slices that map the container's
// UID 0 / GID 0 to the supplied host UID and GID, with a range of 1.
func DefaultMapping(hostUID, hostGID int) ([]syscall.SysProcIDMap, []syscall.SysProcIDMap) {
	return []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostUID, Size: 1}},
		[]syscall.SysProcIDMap{{ContainerID: 0, HostID: hostGID, Size: 1}}
}
