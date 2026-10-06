package logging

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Driver struct {
	StdoutPath string
	StderrPath string
}

func (d Driver) Open() (io.WriteCloser, io.WriteCloser, error) {
	out, err := openTimestamped(d.StdoutPath)
	if err != nil {
		return nil, nil, err
	}
	errOut, err := openTimestamped(d.StderrPath)
	if err != nil {
		return nil, nil, errors.Join(err, out.Close())
	}
	return out, errOut, nil
}

// Streams append across automatic retries and later explicit starts.
func openTimestamped(path string) (*timestamped, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("log must be a regular file: %s", path)
	}
	// Separate a fragment left by an abruptly terminated previous owner.
	if info.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
			f.Close()
			return nil, err
		}
		if last[0] != '\n' {
			if _, err := f.WriteString("\n"); err != nil {
				f.Close()
				return nil, err
			}
		}
	}
	return &timestamped{file: f, lineStart: true}, nil
}

type timestamped struct {
	mu        sync.Mutex
	file      *os.File
	lineStart bool
	closed    bool
}

// Prefix logical lines, not arbitrary chunks delivered by os/exec.
func (t *timestamped) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, os.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		if t.lineStart {
			prefix := time.Now().UTC().Format(time.RFC3339Nano) + " "
			if _, err := io.WriteString(t.file, prefix); err != nil {
				return total, err
			}
			t.lineStart = false
		}
		end := bytes.IndexByte(p, '\n') + 1
		if end == 0 {
			end = len(p)
		}
		n, err := t.file.Write(p[:end])
		total += n
		if n > 0 {
			t.lineStart = p[n-1] == '\n'
		}
		if err != nil {
			return total, err
		}
		if n != end {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}

func (t *timestamped) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	var err error
	if !t.lineStart {
		_, err = t.file.WriteString("\n")
	}
	return errors.Join(err, t.file.Sync(), t.file.Close())
}
