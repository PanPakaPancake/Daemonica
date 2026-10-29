package journal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/sysinfo"
)

// LogFiles are the classic log files the log view may read besides journald
// (SPEC §7.2 SOLL). Nothing else is readable through it; rotated files are not.
var LogFiles = []string{
	"/var/log/auth.log",
	"/var/log/syslog",
	"/var/log/kern.log",
	"/var/log/ufw.log",
	"/var/log/dpkg.log",
	"/var/log/apt/history.log",
	"/var/log/apt/term.log",
	"/var/log/unattended-upgrades/unattended-upgrades.log",
	"/var/log/cloud-init.log",
	"/var/log/cloud-init-output.log",
}

// TailWindow is how much of a file's end is searched (the view shows the tail).
const TailWindow = 8 << 20

// LogFile describes an existing allowlisted file.
type LogFile struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// FileQuery reads the end of an allowlisted file.
type FileQuery struct {
	Path  string `json:"path"`
	Lines int    `json:"lines,omitempty"`
	Grep  string `json:"grep,omitempty"` // case-insensitive substring
}

// FileResult are the matching last lines, oldest first.
type FileResult struct {
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"` // older matches exist or only the tail window was searched
	Size      int64    `json:"size"`
}

// ListFiles returns the allowlisted files that exist below root ("" = /).
func ListFiles(root string) []LogFile {
	out := []LogFile{}
	for _, p := range LogFiles {
		fi, err := os.Lstat(root + p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, LogFile{Path: p, Size: fi.Size(), Modified: fi.ModTime().UTC()})
	}
	return out
}

// ReadFile returns the last matching lines of an allowlisted file below root.
func ReadFile(root string, q FileQuery) (FileResult, error) {
	if !slices.Contains(LogFiles, q.Path) {
		return FileResult{}, errors.New("file is not in the log allowlist")
	}
	if len(q.Grep) > MaxGrep || strings.ContainsAny(q.Grep, "\x00\n") {
		return FileResult{}, errors.New("invalid search text")
	}
	n := q.Lines
	if n <= 0 {
		n = DefaultLines
	}
	n = min(n, MaxLines)
	// O_NOFOLLOW: a symlink planted in place of a log file is not followed.
	f, err := os.OpenFile(root+q.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return FileResult{}, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return FileResult{}, errors.New("not a regular file")
	}
	res := FileResult{Lines: []string{}, Size: fi.Size()}
	off := max(fi.Size()-TailWindow, 0)
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return res, err
	}
	if off > 0 {
		res.Truncated = true
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:] // drop the partial first line
		}
	}
	needle := strings.ToLower(q.Grep)
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	var out []string
	budget := MaxResultBytes
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		if l == "" || (needle != "" && !strings.Contains(strings.ToLower(l), needle)) {
			continue
		}
		l = sysinfo.SanitizeText(l, MaxMessageLen)
		if budget -= len(l) + 8; len(out) == n || budget < 0 {
			res.Truncated = true
			break
		}
		out = append(out, l)
	}
	slices.Reverse(out)
	res.Lines = append(res.Lines, out...)
	return res, nil
}
