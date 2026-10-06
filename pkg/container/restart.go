package container

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type RestartPolicy struct {
	Name       string `json:"name"`
	MaxRetries int    `json:"max_retries,omitempty"`
}

func ParseRestart(value string) (RestartPolicy, error) {
	name, count, hasCount := strings.Cut(value, ":")
	p := RestartPolicy{Name: name}
	switch name {
	case "", "no", "always":
		if hasCount {
			return p, fmt.Errorf("only on-failure accepts a retry count")
		}
		if name == "" {
			p.Name = "no"
		}
	case "on-failure":
		p.MaxRetries = 3
		if hasCount {
			n, err := strconv.Atoi(count)
			if err != nil || n < 1 {
				return p, fmt.Errorf("use on-failure or on-failure:N with N >= 1")
			}
			p.MaxRetries = n
		}
	default:
		return p, fmt.Errorf("restart policy must be no, on-failure[:N], or always")
	}
	return p, nil
}

func (p RestartPolicy) Validate() error {
	switch p.Name {
	case "", "no", "always":
		if p.MaxRetries == 0 {
			return nil
		}
	case "on-failure":
		if p.MaxRetries > 0 {
			return nil
		}
	}
	return fmt.Errorf("invalid saved restart policy")
}

// attempts counts automatic restarts already performed in this Start call.
func (p RestartPolicy) ShouldRestart(exitCode, attempts int) (bool, time.Duration) {
	switch p.Name {
	case "always":
		return true, backoff(attempts)
	case "on-failure":
		if exitCode != 0 && attempts < p.MaxRetries {
			return true, backoff(attempts)
		}
	}
	return false, 0
}

func backoff(attempts int) time.Duration {
	d := time.Second
	for i := 0; i < attempts && d < 30*time.Second; i++ {
		d *= 2
	}
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}

// A signal received during cleanup also suppresses automatic restarts.
func consumeStop(signals <-chan os.Signal, stopping *bool) {
	for {
		select {
		case <-signals:
			*stopping = true
		default:
			return
		}
	}
}

func waitBackoff(signals <-chan os.Signal, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-signals:
		return false
	case <-timer.C:
		return true
	}
}
