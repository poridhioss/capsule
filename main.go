package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/poridhioss/capsule/pkg/container"
	"github.com/poridhioss/capsule/pkg/filesystem"
	"github.com/poridhioss/capsule/pkg/image"
	"github.com/poridhioss/capsule/pkg/network"
)

type envFlag []string

func (e *envFlag) String() string { return "" }
func (e *envFlag) Set(value string) error {
	if _, err := container.MergeEnv([]string{value}); err != nil {
		return err
	}
	*e = append(*e, value)
	return nil
}

func main() {
	var code int
	var err error
	uid, gid := unprivilegedHostIDs()
	if len(os.Args) > 1 && os.Args[1] == "child" {
		runtime.LockOSThread()
		code, err = container.Child()
	} else if len(os.Args) > 1 && (os.Args[1] == "pull" || os.Args[1] == "images" || os.Args[1] == "tag" || os.Args[1] == "rmi") {
		err = image.Command(os.Args[1:], uid, gid)
	} else {
		code, err = command(uid, gid)
	}
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "capsule:", err)
		if code == 0 {
			code = 1
		}
	}
	// All lifecycle methods return and run cleanup before this process exits.
	os.Exit(code)
}

func command(uid, gid int) (int, error) {
	var specs []filesystem.Mount
	var ports portFlag
	var env envFlag
	defaultName := os.Getenv("CAPSULE_NAME")
	if defaultName == "" {
		defaultName = "demo"
	}
	f := flag.NewFlagSet("capsule", flag.ContinueOnError)
	name := f.String("name", defaultName, "container name and ID")
	imageName := f.String("image", "alpine:latest", "local or Docker Hub image")
	grace := f.Duration("grace", 5*time.Second, "shutdown grace period stored at creation")
	f.Var(&env, "e", "KEY=VALUE; may be repeated")
	f.Var(&ports, "p", "hostPort:containerPort (TCP/IPv4)")
	f.Var(mountFlag{&specs, filesystem.ParseVolume}, "v", "source:/target[:ro|rw]")
	f.Var(mountFlag{&specs, filesystem.ParseTmpfs}, "tmpfs", "/target[:size=16m,mode=1777]")
	restart := f.String("restart", "no", "no, on-failure[:N], or always")
	healthCommand := f.String("health-cmd", "", "shell command run inside the container")
	healthInterval := f.Duration("health-interval", 2*time.Second, "health check interval")
	healthTimeout := f.Duration("health-timeout", time.Second, "health check timeout")
	healthRetries := f.Int("health-retries", 3, "consecutive failures before unhealthy")
	copyTo := f.String("copy-to", "", "container ID; followed by HOST_FILE /CONTAINER_FILE")
	copyFrom := f.String("copy-from", "", "container ID; followed by /CONTAINER_FILE HOST_FILE")
	createOnly := f.Bool("create", false, "save configuration without starting")
	start := f.String("start", "", "start a saved container in the foreground")
	stop := f.String("stop", "", "stop a running container and wait for cleanup")
	remove := f.String("remove", "", "remove a stopped/created container and its writable layer")
	inspect := f.String("inspect", "", "print saved container metadata")
	list := f.Bool("list", false, "list saved containers")
	volumeCreate := f.String("volume-create", "", "create or reuse a named volume")
	volumeList := f.Bool("volume-list", false, "list named volumes")
	volumeRemove := f.String("volume-remove", "", "remove an unused named volume")
	if err := f.Parse(os.Args[1:]); err != nil {
		return 0, err
	}
	if os.Geteuid() != 0 {
		return 1, fmt.Errorf("run capsule with sudo from your normal user account")
	}

	management := map[string]bool{
		"start": *start != "", "stop": *stop != "", "remove": *remove != "",
		"inspect": *inspect != "", "list": *list,
		"copy-to": *copyTo != "", "copy-from": *copyFrom != "",
		"volume-create": *volumeCreate != "", "volume-list": *volumeList, "volume-remove": *volumeRemove != "",
	}
	actions := 0
	for _, enabled := range management {
		if enabled {
			actions++
		}
	}
	if actions > 0 {
		copying := *copyTo != "" || *copyFrom != ""
		extras := len(f.Args()) > 0
		if copying {
			extras = len(f.Args()) != 2
		}
		f.Visit(func(option *flag.Flag) {
			if !management[option.Name] {
				extras = true
			}
		})
		if actions != 1 || extras {
			return 1, fmt.Errorf("use one management flag; copy needs two paths, other management flags take no arguments")
		}
	}
	if *copyTo != "" || *copyFrom != "" {
		id := *copyTo
		if id == "" {
			id = *copyFrom
		}
		c, err := container.Load(id)
		if err != nil {
			return 1, err
		}
		if *copyTo != "" {
			err = container.CopyToContainer(c, f.Arg(0), f.Arg(1))
		} else {
			err = container.CopyFromContainer(c, f.Arg(0), f.Arg(1), uid, gid)
		}
		if err != nil {
			return 1, err
		}
		fmt.Printf("Copied: %s -> %s\n", f.Arg(0), f.Arg(1))
		return 0, nil
	}
	if *list {
		items, err := container.List()
		if err != nil {
			return 1, err
		}
		fmt.Println("NAME\tSTATE\tPID\tEXIT\tRESTARTS\tHEALTH")
		for _, c := range items {
			exit := "-"
			if c.ExitCode != nil {
				exit = strconv.Itoa(*c.ExitCode)
			}
			health := "-"
			if c.Health != nil {
				health = string(c.Health.State)
			}
			fmt.Printf("%s\t%s\t%d\t%s\t%d\t%s\n", c.Name, c.State, c.PID, exit, c.RestartCount, health)
		}
		return 0, nil
	}
	for action, id := range map[string]string{"start": *start, "stop": *stop, "remove": *remove, "inspect": *inspect} {
		if id == "" {
			continue
		}
		c, err := container.Load(id)
		if err != nil {
			return 1, err
		}
		switch action {
		case "start":
			return c.Start(uid, gid)
		case "stop":
			if err := c.Stop(); err != nil {
				return 1, err
			}
			fmt.Printf("Stopped: %s\n", id)
		case "remove":
			if err := c.Remove(); err != nil {
				return 1, err
			}
			fmt.Printf("Removed: %s\n", id)
		case "inspect":
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return 0, encoder.Encode(c)
		}
		return 0, nil
	}
	if *volumeCreate != "" {
		dir, err := filesystem.CreateNamedVolume(*volumeCreate, uid, gid)
		if err != nil {
			return 1, err
		}
		fmt.Printf("Volume ready: %s\nPath: %s\n", *volumeCreate, dir)
		return 0, nil
	}
	if *volumeList {
		names, err := filesystem.ListVolumes()
		if err != nil {
			return 1, err
		}
		fmt.Println("NAME\tPATH")
		for _, n := range names {
			fmt.Printf("%s\t%s\n", n, filepath.Join(filesystem.VolumeRoot, n))
		}
		return 0, nil
	}
	if *volumeRemove != "" {
		if err := filesystem.RemoveNamedVolume(*volumeRemove); err != nil {
			return 1, err
		}
		fmt.Printf("Removed volume: %s\n", *volumeRemove)
		return 0, nil
	}
	policy, err := container.ParseRestart(*restart)
	if err != nil {
		return 1, err
	}
	var hc *container.HealthCheck
	if *healthCommand != "" {
		hc = &container.HealthCheck{Cmd: []string{"/bin/sh", "-c", *healthCommand},
			Interval: *healthInterval, Timeout: *healthTimeout, Retries: *healthRetries}
	} else {
		healthOptions := false
		f.Visit(func(option *flag.Flag) {
			if option.Name == "health-interval" || option.Name == "health-timeout" || option.Name == "health-retries" {
				healthOptions = true
			}
		})
		if healthOptions {
			return 1, fmt.Errorf("health timing flags require --health-cmd")
		}
	}
	c := &container.Container{
		Name: *name, Image: *imageName, Cmd: f.Args(), Env: env, Mounts: specs, Ports: ports,
		UID: uid, GID: gid, Grace: *grace, Restart: policy, HealthCheck: hc,
	}
	if err := c.Create(); err != nil {
		return 1, err
	}
	fmt.Printf("Created: %s\n", c.ID)
	if *createOnly {
		return 0, nil
	}
	return c.Start(uid, gid)
}

// Each occurrence of -v or --tmpfs appends one parsed mount specification.
type mountFlag struct {
	specs *[]filesystem.Mount
	parse func(string) (filesystem.Mount, error)
}

func (f mountFlag) String() string { return "" }

func (f mountFlag) Set(value string) error {
	spec, err := f.parse(value)
	if err != nil {
		return err
	}
	*f.specs = append(*f.specs, spec)
	return nil
}

type portFlag []network.PortMapping

func (p *portFlag) String() string { return "" }

func (p *portFlag) Set(value string) error {
	mapping, err := network.ParsePort(value)
	if err != nil {
		return err
	}
	*p = append(*p, mapping)
	return nil
}

func unprivilegedHostIDs() (int, int) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 {
		return 65534, 65534
	}
	return uid, gid
}
