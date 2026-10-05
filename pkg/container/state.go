package container

import "fmt"

type State string

const (
	StateCreated State = "created"
	StateRunning State = "running"
	StateStopped State = "stopped"
	StateRemoved State = "removed"
)

func (c *Container) transition(next State) error {
	allowed := (c.State == StateCreated && (next == StateRunning || next == StateStopped || next == StateRemoved)) ||
		(c.State == StateRunning && next == StateStopped) ||
		(c.State == StateStopped && (next == StateRunning || next == StateRemoved))
	if !allowed {
		return fmt.Errorf("invalid container transition: %s -> %s", c.State, next)
	}
	c.State = next
	return nil
}
