package container

import (
	"fmt"
	"regexp"
	"strings"
)

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Keep the workload environment explicit instead of copying host credentials.
func MergeEnv(overrides []string) ([]string, error) {
	result := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root", "TERM=xterm",
	}
	indexes := map[string]int{"PATH": 0, "HOME": 1, "TERM": 2}
	for _, entry := range overrides {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || !envKey.MatchString(key) || strings.ContainsRune(entry, '\x00') {
			return nil, fmt.Errorf("invalid environment entry %q: use KEY=VALUE", entry)
		}
		if index, exists := indexes[key]; exists {
			result[index] = entry
		} else {
			indexes[key] = len(result)
			result = append(result, entry)
		}
	}
	return result, nil
}
