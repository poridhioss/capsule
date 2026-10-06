package logging

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// n == -1 prints all existing content; n == 0 prints no existing content.
func Tail(path string, n int, w io.Writer) error {
	return read(context.Background(), path, n, false, w)
}

func Follow(ctx context.Context, path string, n int, w io.Writer) error {
	return read(ctx, path, n, true, w)
}

func read(ctx context.Context, path string, n int, follow bool, w io.Writer) error {
	if n < -1 {
		return fmt.Errorf("tail must be -1 or a nonnegative number")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("log must be a regular file")
	}
	start, err := tailOffset(f, info.Size(), n)
	if err != nil {
		return err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	// One initial snapshot, then the same descriptor and offset for follow.
	if _, err := io.CopyN(w, f, info.Size()-start); err != nil {
		return err
	}
	if !follow {
		return nil
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	buffer := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, err := f.Read(buffer)
		if n > 0 {
			written, writeErr := w.Write(buffer[:n])
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if err == io.EOF {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		} else if err != nil {
			return err
		}
	}
}

// Scan backwards in fixed-size blocks, without loading the whole log.
func tailOffset(f *os.File, size int64, n int) (int64, error) {
	if n == -1 {
		return 0, nil
	}
	if n == 0 {
		return size, nil
	}
	buffer := make([]byte, 8192)
	position, lines := size, 0
	for position > 0 {
		begin := position - int64(len(buffer))
		if begin < 0 {
			begin = 0
		}
		chunk := buffer[:int(position-begin)]
		if _, err := f.ReadAt(chunk, begin); err != nil {
			return 0, err
		}
		for i := len(chunk) - 1; i >= 0; i-- {
			absolute := begin + int64(i)
			if chunk[i] == '\n' && absolute != size-1 {
				lines++
				if lines == n {
					return absolute + 1, nil
				}
			}
		}
		position = begin
	}
	return 0, nil
}
