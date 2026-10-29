package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Rotation defaults (SPEC §3.8): at most (Keep+1) * MaxSize on disk; the
// journald mirror keeps its own copy under journald's retention.
const (
	DefaultMaxSize = 32 << 20
	DefaultKeep    = 4
)

// fsAppendFL is FS_APPEND_FL from linux/fs.h.
const fsAppendFL = 0x00000020

// setAppendOnly sets or clears FS_APPEND_FL ("chattr +a") on f. It fails on
// file systems without the flag or without CAP_LINUX_IMMUTABLE.
func setAppendOnly(f *os.File, on bool) error {
	fd := int(f.Fd()) //nolint:gosec // file descriptors fit int
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	if on {
		flags |= fsAppendFL
	} else {
		flags &^= fsAppendFL
	}
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags))
}

func setAppendOnlyPath(p string, on bool) error {
	f, err := os.Open(p) //nolint:gosec // rotated audit files next to the configured path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return setAppendOnly(f, on)
}

// rotated returns the name of rotated file i (audit.log.1 is the newest).
func rotated(path string, i int) string { return path + "." + strconv.Itoa(i) }

// Files returns the existing log files of path, oldest first, ending with path.
func Files(path string, keep int) []string {
	var out []string
	for i := keep; i >= 1; i-- {
		if _, err := os.Stat(rotated(path, i)); err == nil {
			out = append(out, rotated(path, i))
		}
	}
	return append(out, path)
}

// OpenAll opens all log files of path as one stream, oldest record first, so
// queries and verification cover rotated files too.
func OpenAll(path string, keep int) (io.ReadCloser, error) {
	var rs []io.Reader
	var fs []*os.File
	for _, p := range Files(path, keep) {
		f, err := os.Open(p) //nolint:gosec // audit files next to the configured path
		if err != nil {
			if p != path && errors.Is(err, os.ErrNotExist) {
				continue // rotated away meanwhile
			}
			for _, o := range fs {
				_ = o.Close()
			}
			return nil, err
		}
		fs = append(fs, f)
		rs = append(rs, f)
	}
	return multiCloser{io.MultiReader(rs...), fs}, nil
}

type multiCloser struct {
	io.Reader
	fs []*os.File
}

func (m multiCloser) Close() error {
	for _, f := range m.fs {
		_ = f.Close()
	}
	return nil
}

// VerifyAll verifies the chain across all files of path, oldest first. A
// single file must start at GenesisHash. When rotated files exist, the oldest
// one may start with the last hash of a file that was rotated away; that hash
// is accepted as the anchor and reported in Anchor.
func VerifyAll(path string, keep int) VerifyResult {
	files := Files(path, keep)
	anchor := GenesisHash
	res := VerifyResult{Files: len(files)}
	for i, p := range files {
		f, err := os.Open(p) //nolint:gosec // audit files next to the configured path
		if err != nil {
			return VerifyResult{Records: res.Records, Files: len(files), File: p, Problem: "not readable"}
		}
		if i == 0 && len(files) > 1 {
			if prev := firstPrev(f); prev != "" && prev != GenesisHash {
				anchor, res.Anchor = prev, prev
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				_ = f.Close()
				return VerifyResult{Records: res.Records, Files: len(files), File: p, Problem: err.Error()}
			}
		}
		r := Verify(f, anchor)
		_ = f.Close()
		res.Records += r.Records
		if !r.OK {
			r.Records, r.Files, r.File, r.Anchor = res.Records, len(files), p, res.Anchor
			return r
		}
		if r.Records > 0 {
			anchor = r.LastHash
		}
	}
	res.OK, res.LastHash = true, anchor
	return res
}

// firstPrev returns the prev_hash of the first record ("" for an empty or unreadable file).
func firstPrev(r io.Reader) string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	if !sc.Scan() {
		return ""
	}
	var ev Event
	if json.Unmarshal(sc.Bytes(), &ev) != nil {
		return ""
	}
	return ev.PrevHash
}

// rotate moves the current file to path.1 (shifting older files up to Keep)
// and continues the chain in a new file. Called with l.mu held.
func (l *Logger) rotate() error {
	if l.path == "" || l.Keep < 1 {
		return nil
	}
	if l.AppendOnly {
		_ = setAppendOnly(l.f, false)
	}
	if err := l.f.Close(); err != nil {
		return err
	}
	oldest := rotated(l.path, l.Keep)
	_ = setAppendOnlyPath(oldest, false)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return l.reopen(fmt.Errorf("audit: remove %s: %w", oldest, err))
	}
	for i := l.Keep - 1; i >= 0; i-- {
		src := l.path
		if i > 0 {
			src = rotated(l.path, i)
		}
		if _, err := os.Stat(src); err != nil {
			continue
		}
		_ = setAppendOnlyPath(src, false) // renaming an append-only file is refused
		dst := rotated(l.path, i+1)
		if err := os.Rename(src, dst); err != nil {
			return l.reopen(fmt.Errorf("audit: rotate %s: %w", src, err))
		}
		if l.AppendOnly {
			_ = setAppendOnlyPath(dst, true)
		}
	}
	return l.reopen(nil)
}

// reopen opens (or creates) the current file again after a rotation attempt.
func (l *Logger) reopen(cause error) error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640) //nolint:gosec // fixed path from config
	if err != nil {
		return errors.Join(cause, err)
	}
	l.f = f
	if l.AppendOnly {
		_ = setAppendOnly(f, true)
	}
	return cause
}
