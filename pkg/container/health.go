package container

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type Health string

const (
	HealthStarting  Health = "starting"
	HealthHealthy   Health = "healthy"
	HealthUnhealthy Health = "unhealthy"
)

type HealthCheck struct {
	Cmd      []string      `json:"cmd"`
	Interval time.Duration `json:"interval_ns"`
	Timeout  time.Duration `json:"timeout_ns"`
	Retries  int           `json:"retries"`
}

type HealthStatus struct {
	State    Health     `json:"state"`
	Failures int        `json:"consecutive_failures"`
	ExitCode *int       `json:"exit_code,omitempty"`
	Checked  *time.Time `json:"checked_at,omitempty"`
}

func (h *HealthCheck) Validate() error {
	if h == nil {
		return nil
	}
	if len(h.Cmd) == 0 || h.Cmd[0] == "" || h.Interval < 100*time.Millisecond ||
		h.Timeout < 100*time.Millisecond || h.Timeout > time.Minute || h.Retries < 1 {
		return fmt.Errorf("health check needs a command, interval >= 100ms, timeout 100ms..1m, and retries >= 1")
	}
	return nil
}

func (h *HealthStatus) record(code, retries int) {
	now := time.Now().UTC()
	h.ExitCode, h.Checked = &code, &now
	if code == 0 {
		h.Failures, h.State = 0, HealthHealthy
	} else {
		h.Failures++
		if h.Failures >= retries {
			h.State = HealthUnhealthy
		}
	}
}

// The host owner is the sole metadata writer. This goroutine only decodes.
func readHealth(r *os.File) (<-chan HealthStatus, func()) {
	updates := make(chan HealthStatus, 4)
	stop := make(chan struct{})
	go func() {
		defer close(updates)
		decoder := json.NewDecoder(r)
		for {
			var status HealthStatus
			if err := decoder.Decode(&status); err != nil {
				return
			}
			select {
			case updates <- status:
			case <-stop:
				return
			}
		}
	}()
	return updates, func() { close(stop); _ = r.Close() }
}

type childExit struct {
	pid    int
	status syscall.WaitStatus
	err    error
}

// One reaper owns every wait inside PID 1, including health probes and orphans.
func reapChildren(events chan<- childExit, stop <-chan struct{}) {
	defer close(events)
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.ECHILD) {
			return
		}
		select {
		case events <- childExit{pid, status, err}:
		case <-stop:
			return
		}
		if err != nil {
			return
		}
	}
}

func waitCode(status syscall.WaitStatus) int {
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return status.ExitStatus()
}

// Called after PivotRoot, so probes inherit the same namespaces and rootfs.
func superviseWorkload(cmd *exec.Cmd, signals <-chan os.Signal, hc *HealthCheck,
	report io.Writer, ready *os.File) (int, error) {
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	mainPID := cmd.Process.Pid
	defer cmd.Process.Release()
	if ready != nil {
		if _, err := ready.Write([]byte{2}); err != nil {
			_ = syscall.Kill(-mainPID, syscall.SIGKILL)
			return 1, err
		}
		_ = ready.Close()
	}
	events, finished := make(chan childExit, 16), make(chan struct{})
	defer close(finished)
	go reapChildren(events, finished)
	var ticks <-chan time.Time
	if hc != nil {
		ticker := time.NewTicker(hc.Interval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	status := HealthStatus{State: HealthStarting}
	encoder := json.NewEncoder(report)
	emit := func(code int) error {
		status.record(code, hc.Retries)
		return encoder.Encode(status)
	}
	var probe *exec.Cmd
	var probePID int
	var timer *time.Timer
	var deadline <-chan time.Time
	var timedOut, stopping bool
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		if probe != nil {
			_ = syscall.Kill(-probePID, syscall.SIGKILL)
			_ = probe.Process.Release()
		}
	}()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return 1, fmt.Errorf("init reaper ended before receiving the workload status")
			}
			if event.err != nil {
				return 1, event.err
			}
			if event.pid == mainPID {
				return waitCode(event.status), nil
			}
			if probe == nil || event.pid != probePID {
				continue // An adopted child was reaped.
			}
			_ = syscall.Kill(-probePID, syscall.SIGKILL)
			_ = probe.Process.Release()
			probe = nil
			timer.Stop()
			deadline = nil
			code := waitCode(event.status)
			if timedOut {
				code = 124
			}
			if !stopping {
				if err := emit(code); err != nil {
					return 1, err
				}
			}
		case <-ticks:
			if probe != nil || stopping {
				continue // At most one health probe runs at a time.
			}
			next := exec.Command(hc.Cmd[0], hc.Cmd[1:]...)
			next.Env = os.Environ()
			next.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			// Nil stdio uses /dev/null; no os/exec copy goroutines need Wait.
			if err := next.Start(); err != nil {
				if err := emit(127); err != nil {
					return 1, err
				}
				continue
			}
			probe, probePID, timedOut = next, next.Process.Pid, false
			timer = time.NewTimer(hc.Timeout)
			deadline = timer.C
		case <-deadline:
			timedOut, deadline = true, nil
			_ = syscall.Kill(-probePID, syscall.SIGKILL)
		case sig := <-signals:
			stopping, ticks = true, nil
			if probe != nil {
				_ = syscall.Kill(-probePID, syscall.SIGKILL)
			}
			if err := syscall.Kill(-mainPID, sig.(syscall.Signal)); err != nil && !errors.Is(err, syscall.ESRCH) {
				return 1, fmt.Errorf("forward signal to workload: %w", err)
			}
		}
	}
}
