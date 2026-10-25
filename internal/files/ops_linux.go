//go:build linux

package files

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/worker"
)

// Guard carries the helper's verdict for sensitive paths. The helper always
// overwrites it (confirmation by the user AND a fresh step-up); a value sent
// by the browser never reaches the worker.
type Guard struct {
	SensitiveOK bool `json:"sensitive_ok,omitempty"`
}

// Entry describes one directory entry.
type Entry struct {
	Name       string    `json:"name"`              // the name; for non-UTF-8 names its escaped form
	Raw        string    `json:"raw,omitempty"`     // base64 of the name bytes if not valid UTF-8
	Display    string    `json:"display,omitempty"` // escaped form if the name contains invisible characters
	Type       string    `json:"type"`              // file, dir, symlink, fifo, socket, char, block
	Size       int64     `json:"size"`
	Mode       uint32    `json:"mode"` // permission and special bits (07777)
	UID        uint32    `json:"uid"`
	GID        uint32    `json:"gid"`
	User       string    `json:"user,omitempty"`
	Group      string    `json:"group,omitempty"`
	MTime      time.Time `json:"mtime"`
	Target     string    `json:"target,omitempty"`      // symlink target (escaped)
	TargetType string    `json:"target_type,omitempty"` // what the symlink points to ("" = dangling)
	Blocked    bool      `json:"blocked,omitempty"`
}

// kindOf groups entry types for the list filter.
func kindOf(e Entry) string {
	switch e.Type {
	case "dir", "file", "symlink":
		return e.Type
	}
	return "other"
}

// ownerOf is "user:group" with numeric ids where no name is known.
func ownerOf(e Entry) string {
	u, g := e.User, e.Group
	if u == "" {
		u = strconv.FormatUint(uint64(e.UID), 10)
	}
	if g == "" {
		g = strconv.FormatUint(uint64(e.GID), 10)
	}
	return u + ":" + g
}

func typeOf(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "file"
	case unix.S_IFDIR:
		return "dir"
	case unix.S_IFLNK:
		return "symlink"
	case unix.S_IFIFO:
		return "fifo"
	case unix.S_IFSOCK:
		return "socket"
	case unix.S_IFCHR:
		return "char"
	case unix.S_IFBLK:
		return "block"
	}
	return "other"
}

func ts(t unix.Timespec) time.Time { return time.Unix(t.Sec, t.Nsec).UTC() }

func sxts(t unix.StatxTimestamp) time.Time { return time.Unix(t.Sec, int64(t.Nsec)).UTC() }

func newEntry(name string, mode, uid, gid uint32, size int64, mtime time.Time, ids *idNames) Entry {
	e := Entry{Name: name, Type: typeOf(mode), Size: size, Mode: mode & 0o7777, UID: uid, GID: gid, MTime: mtime,
		User: ids.user(uid), Group: ids.group(gid)}
	if !utf8.ValidString(name) {
		e.Raw = base64.StdEncoding.EncodeToString([]byte(name))
		e.Name = Display(name)
	} else if d := Display(name); d != name {
		e.Display = d
	}
	return e
}

// --- user/group names (parsed from /etc/passwd and /etc/group) ---

type idNames struct {
	loaded        bool
	users, groups map[uint32]string
	uids, gids    map[string]uint32
}

func (n *idNames) load() {
	if n.loaded {
		return
	}
	n.loaded = true
	n.users, n.uids = parseIDs("/etc/passwd")
	n.groups, n.gids = parseIDs("/etc/group")
}

func parseIDs(file string) (map[uint32]string, map[string]uint32) {
	byID, byName := map[uint32]string{}, map[string]uint32{}
	b, err := os.ReadFile(file) //nolint:gosec // fixed system path
	if err != nil {
		return byID, byName
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), ":", 4)
		if len(f) < 3 {
			continue
		}
		id, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			continue
		}
		if _, dup := byID[uint32(id)]; !dup {
			byID[uint32(id)] = f[0]
		}
		byName[f[0]] = uint32(id)
	}
	return byID, byName
}

func (n *idNames) user(id uint32) string  { n.load(); return n.users[id] }
func (n *idNames) group(id uint32) string { n.load(); return n.groups[id] }

// --- low-level helpers ---

func mapErr(err error) error {
	var en unix.Errno
	if !errors.As(err, &en) {
		return err
	}
	switch en {
	case unix.ENOENT:
		return opErr(CodeNotFound, "")
	case unix.EACCES, unix.EPERM:
		return opErr(CodeDenied, "")
	case unix.EEXIST:
		return opErr(CodeExists, "")
	case unix.ENOTEMPTY:
		return opErr(CodeNotEmpty, "")
	case unix.ELOOP:
		return opErr(CodeSymlink, "")
	case unix.ENOTDIR:
		return opErr(CodeNotDir, "")
	case unix.EISDIR:
		return opErr(CodeIsDir, "")
	case unix.ENOSPC, unix.EDQUOT:
		return opErr(CodeNoSpace, "")
	case unix.EROFS:
		return opErr(CodeReadOnlyFS, "")
	case unix.EBUSY, unix.ETXTBSY:
		return opErr(CodeBusy, "")
	case unix.ENAMETOOLONG, unix.EINVAL:
		return opErr(CodeInvalid, "")
	case unix.ENOSYS, unix.EOPNOTSUPP:
		return opErr(CodeUnsupported, "")
	case unix.EFBIG:
		return opErr(CodeTooLarge, "")
	case unix.EXDEV:
		return opErr(CodeMountPoint, "")
	}
	return err
}

func openat2(dirfd int, p string, flags int, resolve uint64) (int, error) {
	how := &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC), Resolve: resolve} //nolint:gosec // flags are positive constants
	for i := 0; ; i++ {
		fd, err := unix.Openat2(dirfd, p, how)
		if (errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN)) && i < 8 {
			continue
		}
		return fd, err
	}
}

func procPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

// realPath returns the canonical path of an open descriptor.
func realPath(fd int) (string, error) {
	p, err := os.Readlink(procPath(fd))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, " (deleted)") {
		return "", errors.New("files: object has no path")
	}
	return p, nil
}

type dirH struct {
	fd   int
	path string
}

// openDir opens directory p. write=true refuses symlinks anywhere in the path
// and returns an O_PATH descriptor usable for *at() calls even on
// write-only directories.
func openDir(p string, write bool) (*dirH, error) {
	if !ValidPath(p) {
		return nil, opErr(CodeInvalid, "invalid path")
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY
	res := uint64(unix.RESOLVE_NO_MAGICLINKS)
	if write {
		flags = unix.O_PATH | unix.O_DIRECTORY
		res |= unix.RESOLVE_NO_SYMLINKS
	}
	fd, err := openat2(unix.AT_FDCWD, p, flags, res)
	if err != nil {
		return nil, mapErr(err)
	}
	rp, err := realPath(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, opErr(CodeUnsupported, "cannot resolve path")
	}
	if Blocked(rp) {
		_ = unix.Close(fd)
		return nil, opErr(CodeBlocked, "")
	}
	return &dirH{fd: fd, path: rp}, nil
}

func (d *dirH) close() { _ = unix.Close(d.fd) }

func readlinkat(dirfd int, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func randName() string {
	var b [9]byte
	_, _ = rand.Read(b[:])
	return ".daemonica-" + base64.RawURLEncoding.EncodeToString(b[:]) + ".part"
}

func writable(dirfd int) bool { return unix.Faccessat(dirfd, ".", unix.W_OK|unix.X_OK, 0) == nil }

// --- list / stat ---

// ListArgs are the inputs of fs.list.
type ListArgs struct {
	Path     string `json:"path"`
	Hidden   bool   `json:"hidden,omitempty"`
	Filter   string `json:"filter,omitempty"`
	Sort     string `json:"sort,omitempty"`  // name (default), size, mtime, type, mode, owner
	Owner    string `json:"owner,omitempty"` // substring of "user:group" (or numeric ids)
	Kind     string `json:"kind,omitempty"`  // dir, file, symlink, other
	Desc     bool   `json:"desc,omitempty"`
	Offset   int    `json:"offset,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	DirsOnly bool   `json:"dirs_only,omitempty"`
}

// ListResult is one page of a directory.
type ListResult struct {
	Path      string  `json:"path"` // canonical path (symlinks resolved)
	Entries   []Entry `json:"entries"`
	Total     int     `json:"total"`
	Truncated bool    `json:"truncated,omitempty"` // directory has more than ListCap entries
	Writable  bool    `json:"writable"`
	Virtual   bool    `json:"virtual,omitempty"`
}

func isDirEntry(e Entry) bool {
	return e.Type == "dir" || (e.Type == "symlink" && e.TargetType == "dir")
}

// List returns a sorted, filtered page of directory a.Path.
func List(a ListArgs) (ListResult, error) {
	d, err := openDir(a.Path, false)
	if err != nil {
		return ListResult{}, err
	}
	f := os.NewFile(uintptr(d.fd), d.path) //nolint:gosec // fd from openat2
	defer func() { _ = f.Close() }()
	res := ListResult{Path: d.path, Entries: []Entry{}, Writable: writable(d.fd), Virtual: Virtual(d.path)}
	var names []string
	for {
		batch, rerr := f.Readdirnames(4096)
		names = append(names, batch...)
		if len(names) > ListCap {
			names, res.Truncated = names[:ListCap], true
			break
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return res, mapErr(rerr)
		}
	}
	filter := strings.ToLower(strings.TrimSpace(a.Filter))
	owner := strings.ToLower(strings.TrimSpace(a.Owner))
	ids := &idNames{}
	all := make([]Entry, 0, len(names))
	for _, n := range names {
		if !a.Hidden && strings.HasPrefix(n, ".") {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(Display(n)), filter) {
			continue
		}
		var st unix.Stat_t
		if unix.Fstatat(d.fd, n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
			continue // vanished meanwhile
		}
		e := newEntry(n, st.Mode, st.Uid, st.Gid, st.Size, ts(st.Mtim), ids)
		if e.Type == "symlink" {
			if t, err := readlinkat(d.fd, n); err == nil {
				e.Target = Display(t)
			}
			var tst unix.Stat_t
			if unix.Fstatat(d.fd, n, &tst, 0) == nil {
				e.TargetType = typeOf(tst.Mode)
			}
		}
		if a.DirsOnly && !isDirEntry(e) {
			continue
		}
		if a.Kind != "" && kindOf(e) != a.Kind {
			continue
		}
		if owner != "" && !strings.Contains(strings.ToLower(ownerOf(e))+" "+strconv.FormatUint(uint64(e.UID), 10)+":"+strconv.FormatUint(uint64(e.GID), 10), owner) {
			continue
		}
		e.Blocked = Blocked(Join(d.path, n))
		all = append(all, e)
	}
	less := func(i, j int) bool {
		x, y := all[i], all[j]
		switch a.Sort {
		case "size":
			if x.Size != y.Size {
				return x.Size < y.Size
			}
		case "mtime":
			if !x.MTime.Equal(y.MTime) {
				return x.MTime.Before(y.MTime)
			}
		case "type":
			if x.Type != y.Type {
				return x.Type < y.Type
			}
		case "mode":
			if x.Mode != y.Mode {
				return x.Mode < y.Mode
			}
		case "owner":
			if ox, oy := strings.ToLower(ownerOf(x)), strings.ToLower(ownerOf(y)); ox != oy {
				return ox < oy
			}
		}
		lx, ly := strings.ToLower(x.Name), strings.ToLower(y.Name)
		if lx != ly {
			return lx < ly
		}
		return x.Name < y.Name
	}
	sort.SliceStable(all, func(i, j int) bool {
		di, dj := isDirEntry(all[i]), isDirEntry(all[j])
		if di != dj {
			return di // directories first, regardless of direction
		}
		if a.Desc {
			return less(j, i)
		}
		return less(i, j)
	})
	res.Total = len(all)
	limit := a.Limit
	if limit <= 0 {
		limit = 200
	}
	limit = min(limit, PageMax)
	off := min(max(a.Offset, 0), len(all))
	res.Entries = all[off:min(off+limit, len(all))]
	return res, nil
}

// StatResult describes one object in detail.
type StatResult struct {
	Entry
	Path      string     `json:"path"`
	ATime     time.Time  `json:"atime"`
	CTime     time.Time  `json:"ctime"`
	BTime     *time.Time `json:"btime,omitempty"`
	Nlink     uint32     `json:"nlink"`
	Inode     uint64     `json:"inode"`
	Readable  bool       `json:"readable"`
	Writable  bool       `json:"writable"`
	Sensitive bool       `json:"sensitive,omitempty"`
	Virtual   bool       `json:"virtual,omitempty"`
}

// StatArgs are the inputs of fs.stat.
type StatArgs struct {
	Target
	// Regular requires a readable regular file (download preflight).
	Regular bool `json:"regular,omitempty"`
	Guard
}

// Stat describes a.Target without following a final symlink. With Regular
// it instead resolves the target like a read would and applies the read rules.
func Stat(a StatArgs) (StatResult, error) {
	dir, name, err := a.Resolve()
	if err != nil {
		return StatResult{}, err
	}
	d, err := openDir(dir, false)
	if err != nil {
		return StatResult{}, err
	}
	defer d.close()
	p := Join(d.path, name)
	if a.Regular {
		fd, rp, st, err := openRead(d, name, a.Guard, false)
		if err != nil {
			return StatResult{}, err
		}
		_ = unix.Close(fd)
		ids := &idNames{}
		r := StatResult{Entry: newEntry(path.Base(rp), st.Mode, st.Uid, st.Gid, st.Size, ts(st.Mtim), ids), Path: rp,
			Readable: true, Sensitive: Sensitive(rp)}
		return r, nil
	}
	if Blocked(p) {
		return StatResult{}, opErr(CodeBlocked, "")
	}
	var sx unix.Statx_t
	if err := unix.Statx(d.fd, name, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_BTIME, &sx); err != nil {
		return StatResult{}, mapErr(err)
	}
	ids := &idNames{}
	r := StatResult{Entry: newEntry(name, uint32(sx.Mode), sx.Uid, sx.Gid, int64(sx.Size), sxts(sx.Mtime), ids), //nolint:gosec // sizes fit
		Path: p, ATime: sxts(sx.Atime), CTime: sxts(sx.Ctime), Nlink: sx.Nlink, Inode: sx.Ino,
		Sensitive: Sensitive(p), Virtual: Virtual(p)}
	if sx.Mask&unix.STATX_BTIME != 0 {
		bt := sxts(sx.Btime)
		r.BTime = &bt
	}
	if r.Type == "symlink" {
		if t, err := readlinkat(d.fd, name); err == nil {
			r.Target = Display(t)
		}
		var tst unix.Stat_t
		if unix.Fstatat(d.fd, name, &tst, 0) == nil {
			r.TargetType = typeOf(tst.Mode)
		}
	} else {
		r.Readable = unix.Faccessat(d.fd, name, unix.R_OK, 0) == nil
		r.Writable = unix.Faccessat(d.fd, name, unix.W_OK, 0) == nil
	}
	return r, nil
}

// --- create / rename / chmod / chown ---

// CreateArgs are the inputs of fs.create (Kind "file" or "dir").
type CreateArgs struct {
	Dir  string `json:"dir"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	Mode uint32 `json:"mode,omitempty"`
}

// PathResult returns the canonical path of the affected object.
type PathResult struct {
	Path string `json:"path"`
}

// Create makes an empty file or directory (never overwriting).
func Create(a CreateArgs) (PathResult, error) {
	if !ValidName(a.Name) {
		return PathResult{}, opErr(CodeInvalid, "invalid name")
	}
	d, err := openDir(a.Dir, true)
	if err != nil {
		return PathResult{}, err
	}
	defer d.close()
	p := Join(d.path, a.Name)
	if Blocked(p) {
		return PathResult{}, opErr(CodeBlocked, "")
	}
	if Virtual(p) {
		return PathResult{}, opErr(CodeVirtual, "")
	}
	unix.Umask(0)
	switch a.Kind {
	case "dir":
		mode := a.Mode & 0o7777
		if mode == 0 {
			mode = 0o750
		}
		if err := unix.Mkdirat(d.fd, a.Name, mode); err != nil {
			return PathResult{}, mapErr(err)
		}
	case "file":
		mode := a.Mode & 0o777
		if mode == 0 {
			mode = 0o640
		}
		fd, err := unix.Openat(d.fd, a.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
		if err != nil {
			return PathResult{}, mapErr(err)
		}
		_ = unix.Close(fd)
	default:
		return PathResult{}, opErr(CodeInvalid, "invalid kind")
	}
	return PathResult{Path: p}, nil
}

// RenameArgs are the inputs of fs.rename (within one directory).
type RenameArgs struct {
	Target
	NewName string `json:"new_name"`
	Guard
}

func checkMutable(p string, g Guard) error {
	switch {
	case Blocked(p):
		return opErr(CodeBlocked, "")
	case Protected(p) || ContainsBlocked(p):
		return opErr(CodeProtected, "")
	case Virtual(p):
		return opErr(CodeVirtual, "")
	case Sensitive(p) && !g.SensitiveOK:
		return opErr(CodeSensitive, "")
	}
	return nil
}

// renameNoReplace renames without ever replacing an existing destination.
func renameNoReplace(sfd int, sname string, dfd int, dname string) error {
	err := unix.Renameat2(sfd, sname, dfd, dname, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		// File system without RENAME_NOREPLACE: check, then rename (small race,
		// but only within the user's own permissions).
		var st unix.Stat_t
		if unix.Fstatat(dfd, dname, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
			return unix.EEXIST
		}
		err = unix.Renameat(sfd, sname, dfd, dname)
	}
	return err
}

// Rename renames an entry inside its directory.
func Rename(a RenameArgs) (PathResult, error) {
	dir, name, err := a.Resolve()
	if err != nil {
		return PathResult{}, err
	}
	if !ValidName(a.NewName) {
		return PathResult{}, opErr(CodeInvalid, "invalid name")
	}
	d, err := openDir(dir, true)
	if err != nil {
		return PathResult{}, err
	}
	defer d.close()
	if err := checkMutable(Join(d.path, name), a.Guard); err != nil {
		return PathResult{}, err
	}
	dst := Join(d.path, a.NewName)
	if Blocked(dst) {
		return PathResult{}, opErr(CodeBlocked, "")
	}
	if err := renameNoReplace(d.fd, name, d.fd, a.NewName); err != nil {
		return PathResult{}, mapErr(err)
	}
	return PathResult{Path: dst}, nil
}

// ChmodArgs are the inputs of fs.chmod.
type ChmodArgs struct {
	Target
	Mode uint32 `json:"mode"`
	Guard
}

// openNoFollow opens the final component as O_PATH without following a
// symlink and refuses symlinks (whose own mode/owner are meaningless here).
func openNoFollow(d *dirH, name string) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat(d.fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, st, mapErr(err)
	}
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, st, mapErr(err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = unix.Close(fd)
		return -1, st, opErr(CodeSymlink, "")
	}
	return fd, st, nil
}

// Chmod changes permission bits (Linux decides: owner or root only).
func Chmod(a ChmodArgs) (PathResult, error) {
	dir, name, err := a.Resolve()
	if err != nil {
		return PathResult{}, err
	}
	if a.Mode > 0o7777 {
		return PathResult{}, opErr(CodeInvalid, "invalid mode")
	}
	d, err := openDir(dir, true)
	if err != nil {
		return PathResult{}, err
	}
	defer d.close()
	p := Join(d.path, name)
	if err := checkRules(p, a.Guard); err != nil {
		return PathResult{}, err
	}
	fd, _, err := openNoFollow(d, name)
	if err != nil {
		return PathResult{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchmodat(unix.AT_FDCWD, procPath(fd), a.Mode, 0); err != nil {
		return PathResult{}, mapErr(err)
	}
	return PathResult{Path: p}, nil
}

// checkRules applies the read/write rules for non-structural changes.
func checkRules(p string, g Guard) error {
	switch {
	case Blocked(p):
		return opErr(CodeBlocked, "")
	case Virtual(p):
		return opErr(CodeVirtual, "")
	case Sensitive(p) && !g.SensitiveOK:
		return opErr(CodeSensitive, "")
	}
	return nil
}

// ChownArgs are the inputs of fs.chown ("" keeps the current value).
type ChownArgs struct {
	Target
	User  string `json:"user,omitempty"`
	Group string `json:"group,omitempty"`
	Guard
}

// Chown changes owner and/or group (root mode only; enforced by the helper and the kernel).
func Chown(a ChownArgs) (PathResult, error) {
	dir, name, err := a.Resolve()
	if err != nil {
		return PathResult{}, err
	}
	ids := &idNames{}
	ids.load()
	uid, gid := -1, -1
	if a.User != "" {
		v, ok := ids.uids[a.User]
		if !ok {
			return PathResult{}, opErr(CodeInvalid, "unknown user")
		}
		uid = int(v)
	}
	if a.Group != "" {
		v, ok := ids.gids[a.Group]
		if !ok {
			return PathResult{}, opErr(CodeInvalid, "unknown group")
		}
		gid = int(v)
	}
	d, err := openDir(dir, true)
	if err != nil {
		return PathResult{}, err
	}
	defer d.close()
	p := Join(d.path, name)
	if err := checkRules(p, a.Guard); err != nil {
		return PathResult{}, err
	}
	fd, _, err := openNoFollow(d, name)
	if err != nil {
		return PathResult{}, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchownat(unix.AT_FDCWD, procPath(fd), uid, gid, 0); err != nil {
		return PathResult{}, mapErr(err)
	}
	return PathResult{Path: p}, nil
}

// --- copy / move / delete ---

type limits struct {
	entries, maxEntries int
	bytes, maxBytes     int64
	deadline            time.Time
	root                bool
	skipped             int
}

func newLimits() *limits {
	return &limits{maxEntries: 200_000, maxBytes: 64 << 30, deadline: time.Now().Add(14 * time.Minute), root: os.Geteuid() == 0}
}

func (l *limits) tick() error {
	l.entries++
	if l.entries > l.maxEntries || time.Now().After(l.deadline) {
		return opErr(CodeLimit, "")
	}
	return nil
}

func readNames(f *os.File) ([]string, error) {
	var all []string
	for {
		b, err := f.Readdirnames(1024)
		all = append(all, b...)
		if errors.Is(err, io.EOF) {
			return all, nil
		}
		if err != nil {
			return all, err
		}
		if len(all) > ListCap {
			return all, opErr(CodeLimit, "")
		}
	}
}

func copyTree(sfd int, sname string, dfd int, dname string, l *limits, depth int) error {
	if depth > TreeMaxDepth {
		return opErr(CodeLimit, "")
	}
	if err := l.tick(); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(sfd, sname, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return mapErr(err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return copyFile(sfd, sname, dfd, dname, l)
	case unix.S_IFDIR:
		in, err := unix.Openat(sfd, sname, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return mapErr(err)
		}
		f := os.NewFile(uintptr(in), sname) //nolint:gosec // fd from openat
		defer func() { _ = f.Close() }()
		if err := unix.Mkdirat(dfd, dname, 0o700); err != nil {
			return mapErr(err)
		}
		out, err := unix.Openat(dfd, dname, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return mapErr(err)
		}
		defer func() { _ = unix.Close(out) }()
		names, err := readNames(f)
		if err != nil {
			return mapErr(err)
		}
		for _, n := range names {
			if err := copyTree(in, n, out, n, l, depth+1); err != nil {
				return err
			}
		}
		if l.root {
			_ = unix.Fchownat(unix.AT_FDCWD, procPath(out), int(st.Uid), int(st.Gid), 0)
		}
		_ = unix.Fchmodat(unix.AT_FDCWD, procPath(out), st.Mode&0o7777, 0)
		return nil
	case unix.S_IFLNK:
		t, err := readlinkat(sfd, sname)
		if err != nil {
			return mapErr(err)
		}
		if err := unix.Symlinkat(t, dfd, dname); err != nil {
			return mapErr(err)
		}
		if l.root {
			_ = unix.Fchownat(dfd, dname, int(st.Uid), int(st.Gid), unix.AT_SYMLINK_NOFOLLOW)
		}
		return nil
	default:
		l.skipped++ // devices, FIFOs and sockets are not copied
		return nil
	}
}

func copyFile(sfd int, sname string, dfd int, dname string, l *limits) error {
	in, err := unix.Openat(sfd, sname, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return mapErr(err)
	}
	fin := os.NewFile(uintptr(in), sname) //nolint:gosec // fd from openat
	defer func() { _ = fin.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(in, &st); err != nil {
		return mapErr(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		l.skipped++
		return nil
	}
	out, err := unix.Openat(dfd, dname, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return mapErr(err)
	}
	fout := os.NewFile(uintptr(out), dname) //nolint:gosec // fd from openat
	defer func() { _ = fout.Close() }()
	n, err := io.Copy(fout, io.LimitReader(fin, l.maxBytes-l.bytes+1))
	l.bytes += n
	if err != nil {
		return mapErr(err)
	}
	if l.bytes > l.maxBytes {
		return opErr(CodeLimit, "")
	}
	if l.root {
		_ = unix.Fchown(out, int(st.Uid), int(st.Gid))
	}
	_ = unix.Fchmod(out, st.Mode&0o7777)
	_ = unix.UtimesNanoAt(dfd, dname, []unix.Timespec{st.Atim, st.Mtim}, unix.AT_SYMLINK_NOFOLLOW)
	return nil
}

// removeTree deletes name below dirfd without following symlinks and
// without crossing into other file systems (mount points).
func removeTree(dirfd int, name string, dev uint64, l *limits, depth int) error {
	if depth > TreeMaxDepth {
		return opErr(CodeLimit, "")
	}
	if err := l.tick(); err != nil {
		return err
	}
	err := unix.Unlinkat(dirfd, name, 0)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if !errors.Is(err, unix.EISDIR) && !errors.Is(err, unix.EPERM) {
		return mapErr(err)
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return mapErr(err)
	}
	f := os.NewFile(uintptr(fd), name) //nolint:gosec // fd from openat
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return mapErr(err)
	}
	if st.Dev != dev {
		return opErr(CodeMountPoint, "")
	}
	for pass := 0; pass < 4; pass++ {
		names, err := readNames(f)
		if err != nil {
			return mapErr(err)
		}
		if len(names) == 0 {
			break
		}
		for _, n := range names {
			if err := removeTree(fd, n, dev, l, depth+1); err != nil {
				return err
			}
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return mapErr(err)
		}
	}
	if err := unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR); err != nil {
		return mapErr(err)
	}
	return nil
}

// TransferArgs are the inputs of fs.transfer (move or copy).
type TransferArgs struct {
	Target
	DestDir string `json:"dest_dir"`
	NewName string `json:"new_name,omitempty"`
	Copy    bool   `json:"copy,omitempty"`
	Guard
}

// TransferResult summarizes a move or copy.
type TransferResult struct {
	Path    string `json:"path"`
	Entries int    `json:"entries"`
	Bytes   int64  `json:"bytes"`
	Skipped int    `json:"skipped,omitempty"`
}

// Transfer moves or copies an entry into DestDir. Moves are renames; across
// file systems they become copy + delete. Existing destinations are never replaced.
func Transfer(a TransferArgs) (TransferResult, error) {
	dir, name, err := a.Resolve()
	if err != nil {
		return TransferResult{}, err
	}
	newName := name
	if a.NewName != "" {
		if !ValidName(a.NewName) {
			return TransferResult{}, opErr(CodeInvalid, "invalid name")
		}
		newName = a.NewName
	}
	s, err := openDir(dir, true)
	if err != nil {
		return TransferResult{}, err
	}
	defer s.close()
	dd, err := openDir(a.DestDir, true)
	if err != nil {
		return TransferResult{}, err
	}
	defer dd.close()
	src, dst := Join(s.path, name), Join(dd.path, newName)
	if a.Copy {
		if err := checkRules(src, a.Guard); err != nil {
			return TransferResult{}, err
		}
	} else if err := checkMutable(src, a.Guard); err != nil {
		return TransferResult{}, err
	}
	if Blocked(dst) {
		return TransferResult{}, opErr(CodeBlocked, "")
	}
	if Virtual(dst) {
		return TransferResult{}, opErr(CodeVirtual, "")
	}
	if dd.path == src || strings.HasPrefix(dd.path, src+"/") {
		return TransferResult{}, opErr(CodeInvalid, "destination inside source")
	}
	res := TransferResult{Path: dst}
	if !a.Copy {
		err := renameNoReplace(s.fd, name, dd.fd, newName)
		if err == nil {
			res.Entries = 1
			return res, nil
		}
		if !errors.Is(err, unix.EXDEV) {
			return res, mapErr(err)
		}
	}
	var dst0 unix.Stat_t
	if unix.Fstatat(dd.fd, newName, &dst0, unix.AT_SYMLINK_NOFOLLOW) == nil {
		return res, opErr(CodeExists, "")
	}
	l := newLimits()
	if err := copyTree(s.fd, name, dd.fd, newName, l, 0); err != nil {
		// Remove the partial copy (it did not exist before: checked above).
		var pst unix.Stat_t
		if unix.Fstat(dd.fd, &pst) == nil {
			_ = removeTree(dd.fd, newName, pst.Dev, newLimits(), 0)
		}
		return res, err
	}
	res.Entries, res.Bytes, res.Skipped = l.entries, l.bytes, l.skipped
	if !a.Copy {
		var st unix.Stat_t
		if err := unix.Fstatat(s.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return res, mapErr(err)
		}
		if err := removeTree(s.fd, name, st.Dev, newLimits(), 0); err != nil {
			return res, err
		}
	}
	return res, nil
}

// DeleteArgs are the inputs of fs.delete.
type DeleteArgs struct {
	Target
	Recursive bool `json:"recursive,omitempty"`
	Guard
}

// DeleteResult counts removed entries.
type DeleteResult struct {
	Entries int `json:"entries"`
}

// Delete removes a file, symlink or (recursively) a directory.
func Delete(a DeleteArgs) (DeleteResult, error) {
	dir, name, err := a.Resolve()
	if err != nil {
		return DeleteResult{}, err
	}
	d, err := openDir(dir, true)
	if err != nil {
		return DeleteResult{}, err
	}
	defer d.close()
	if err := checkMutable(Join(d.path, name), a.Guard); err != nil {
		return DeleteResult{}, err
	}
	var st, pst unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return DeleteResult{}, mapErr(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := unix.Unlinkat(d.fd, name, 0); err != nil {
			return DeleteResult{}, mapErr(err)
		}
		return DeleteResult{Entries: 1}, nil
	}
	if !a.Recursive {
		if err := unix.Unlinkat(d.fd, name, unix.AT_REMOVEDIR); err != nil {
			return DeleteResult{}, mapErr(err)
		}
		return DeleteResult{Entries: 1}, nil
	}
	if err := unix.Fstat(d.fd, &pst); err != nil {
		return DeleteResult{}, mapErr(err)
	}
	if st.Dev != pst.Dev {
		return DeleteResult{}, opErr(CodeMountPoint, "")
	}
	l := newLimits()
	if err := removeTree(d.fd, name, st.Dev, l, 0); err != nil {
		return DeleteResult{Entries: l.entries}, err
	}
	return DeleteResult{Entries: l.entries}, nil
}

// --- reading / downloading ---

// ReadArgs are the inputs of fs.read (editor) and fs.download.
type ReadArgs struct {
	Target
	Edit   bool  `json:"edit,omitempty"`
	Offset int64 `json:"offset,omitempty"`
	Length int64 `json:"length,omitempty"` // 0 = to the end
	Guard
}

// ReadMeta is sent as the first chunk of a read stream.
type ReadMeta struct {
	Path     string    `json:"path"` // canonical path of the file actually opened
	Dir      string    `json:"dir"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	MTime    time.Time `json:"mtime"`
	Mode     uint32    `json:"mode"`
	User     string    `json:"user,omitempty"`
	Group    string    `json:"group,omitempty"`
	Hash     string    `json:"hash,omitempty"`      // sha256 of the content (editor)
	Binary   bool      `json:"binary,omitempty"`    // not valid UTF-8 text: not opened in the editor
	TooLarge bool      `json:"too_large,omitempty"` // above MaxEditBytes
	Writable bool      `json:"writable"`
	Offset   int64     `json:"offset"`
	Length   int64     `json:"length"`
}

// openRead opens name for reading (following a final symlink, never magic
// links) and applies the rules to the canonical path of the opened file.
func openRead(d *dirH, name string, g Guard, edit bool) (int, string, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := openat2(d.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, unix.RESOLVE_NO_MAGICLINKS)
	if err != nil {
		return -1, "", st, mapErr(err)
	}
	fail := func(e error) (int, string, unix.Stat_t, error) { _ = unix.Close(fd); return -1, "", st, e }
	rp, err := realPath(fd)
	if err != nil {
		return fail(opErr(CodeUnsupported, ""))
	}
	if Blocked(rp) {
		return fail(opErr(CodeBlocked, ""))
	}
	if err := unix.Fstat(fd, &st); err != nil {
		return fail(mapErr(err))
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fail(opErr(CodeNotRegular, ""))
	}
	if Virtual(rp) && !edit {
		return fail(opErr(CodeVirtual, ""))
	}
	if Sensitive(rp) && !g.SensitiveOK {
		return fail(opErr(CodeSensitive, ""))
	}
	return fd, rp, st, nil
}

// ReadResult is the final status of a read stream.
type ReadResult struct {
	Bytes int64 `json:"bytes"`
}

// Read streams a file to out: one JSON metadata chunk, then the data.
// In editor mode the content is only sent if it is UTF-8 text within MaxEditBytes.
func Read(a ReadArgs, out io.Writer) (ReadResult, error) {
	dir, name, err := a.Resolve()
	if err != nil {
		return ReadResult{}, err
	}
	d, err := openDir(dir, false)
	if err != nil {
		return ReadResult{}, err
	}
	defer d.close()
	fd, rp, st, err := openRead(d, name, a.Guard, a.Edit)
	if err != nil {
		return ReadResult{}, err
	}
	f := os.NewFile(uintptr(fd), rp) //nolint:gosec // fd from openat2
	defer func() { _ = f.Close() }()
	ids := &idNames{}
	meta := ReadMeta{Path: rp, Dir: path.Dir(rp), Name: path.Base(rp), Size: st.Size, MTime: ts(st.Mtim), Mode: st.Mode & 0o7777,
		User: ids.user(st.Uid), Group: ids.group(st.Gid),
		Writable: unix.Faccessat(unix.AT_FDCWD, procPath(fd), unix.W_OK, 0) == nil}
	cw := rpc.ChunkWriter{W: out}
	sendMeta := func() error {
		b, _ := json.Marshal(meta)
		return rpc.WriteChunk(out, b)
	}
	if a.Edit {
		data, err := io.ReadAll(io.LimitReader(f, MaxEditBytes+1))
		if err != nil {
			return ReadResult{}, mapErr(err)
		}
		switch {
		case len(data) > MaxEditBytes:
			meta.TooLarge, data = true, nil
		case bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data):
			meta.Binary, data = true, nil
		default:
			sum := sha256.Sum256(data)
			meta.Hash = hex.EncodeToString(sum[:])
			meta.Length = int64(len(data))
		}
		if err := sendMeta(); err != nil {
			return ReadResult{}, err
		}
		if _, err := cw.Write(data); err != nil {
			return ReadResult{}, err
		}
		return ReadResult{Bytes: int64(len(data))}, cw.Close()
	}
	if a.Offset < 0 || a.Offset > st.Size || a.Length < 0 {
		return ReadResult{}, opErr(CodeRange, "")
	}
	length := st.Size - a.Offset
	if a.Length > 0 && a.Length < length {
		length = a.Length
	}
	meta.Offset, meta.Length = a.Offset, length
	if err := sendMeta(); err != nil {
		return ReadResult{}, err
	}
	n, err := io.Copy(cw, io.NewSectionReader(f, a.Offset, length))
	if err != nil {
		return ReadResult{Bytes: n}, err
	}
	return ReadResult{Bytes: n}, cw.Close()
}

// --- writing (editor) and uploading ---

// tempFile creates an anonymous file in d (O_TMPFILE, vanishes if the worker
// dies) or, where unsupported, a uniquely named hidden file.
func tempFile(d *dirH) (int, string, error) {
	fd, err := unix.Openat(d.fd, ".", unix.O_TMPFILE|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
	if err == nil {
		return fd, "", nil
	}
	if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EISDIR) && !errors.Is(err, unix.EINVAL) {
		return -1, "", mapErr(err)
	}
	name := randName()
	fd, err = unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return -1, "", mapErr(err)
	}
	return fd, name, nil
}

// commit gives the temp file its final name: replace=false never overwrites.
func commit(d *dirH, fd int, tmpName, name string, replace bool) error {
	if tmpName == "" {
		if !replace {
			if err := unix.Linkat(unix.AT_FDCWD, procPath(fd), d.fd, name, unix.AT_SYMLINK_FOLLOW); err != nil {
				return mapErr(err)
			}
			return nil
		}
		tmpName = randName()
		if err := unix.Linkat(unix.AT_FDCWD, procPath(fd), d.fd, tmpName, unix.AT_SYMLINK_FOLLOW); err != nil {
			return mapErr(err)
		}
	}
	var err error
	if replace {
		err = unix.Renameat(d.fd, tmpName, d.fd, name)
	} else {
		err = unix.Linkat(d.fd, tmpName, d.fd, name, 0)
	}
	_ = unix.Unlinkat(d.fd, tmpName, 0)
	if err != nil {
		return mapErr(err)
	}
	return nil
}

func syncDir(d *dirH) {
	if fd, err := unix.Openat(d.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Fsync(fd)
		_ = unix.Close(fd)
	}
}

func writeAll(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return mapErr(err)
		}
		data = data[n:]
	}
	return nil
}

var errFallback = errors.New("files: fall back to in-place write")

// copyXattrs copies extended attributes (POSIX ACLs, capabilities, …). A
// failure to keep the ACL forces the in-place strategy.
func copyXattrs(src, dst int) error {
	sz, err := unix.Flistxattr(src, nil)
	if err != nil || sz <= 0 {
		return nil
	}
	buf := make([]byte, sz)
	if sz, err = unix.Flistxattr(src, buf); err != nil {
		return nil
	}
	for _, n := range strings.Split(strings.TrimRight(string(buf[:sz]), "\x00"), "\x00") {
		if n == "" {
			continue
		}
		vs, err := unix.Fgetxattr(src, n, nil)
		if err != nil || vs < 0 {
			continue
		}
		v := make([]byte, vs)
		if vs, err = unix.Fgetxattr(src, n, v); err != nil {
			continue
		}
		if err := unix.Fsetxattr(dst, n, v[:vs], 0); err != nil && strings.HasPrefix(n, "system.posix_acl") {
			return errFallback
		}
	}
	return nil
}

// WriteArgs are the inputs of fs.write (editor save).
type WriteArgs struct {
	Target
	ExpectedHash string `json:"expected_hash,omitempty"`
	Create       bool   `json:"create,omitempty"`
	Guard
}

// WriteResult describes the saved file.
type WriteResult struct {
	Path   string    `json:"path"`
	Hash   string    `json:"hash"`
	Size   int64     `json:"size"`
	MTime  time.Time `json:"mtime"`
	Atomic bool      `json:"atomic"`
}

func hashFD(fd int) (string, error) {
	h := sha256.New()
	buf := make([]byte, 256<<10)
	var off int64
	for {
		n, err := unix.Pread(fd, buf, off)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", mapErr(err)
		}
		if n == 0 {
			break
		}
		h.Write(buf[:n])
		off += int64(n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Write saves editor content (read from in) with optimistic concurrency:
// ExpectedHash must match the current content. Owner, group, mode and
// extended attributes are kept. The file is replaced atomically (temp +
// rename) when that preserves everything; otherwise (file owned by someone
// else, hard links, no write access to the directory) it is rewritten in place.
func Write(a WriteArgs, in io.Reader) (WriteResult, error) {
	data, err := io.ReadAll(io.LimitReader(in, MaxEditBytes+1))
	if err != nil {
		return WriteResult{}, opErr(CodeAborted, "")
	}
	if len(data) > MaxEditBytes {
		return WriteResult{}, opErr(CodeTooLarge, "")
	}
	dir, name, err := a.Resolve()
	if err != nil {
		return WriteResult{}, err
	}
	d, err := openDir(dir, true)
	if err != nil {
		return WriteResult{}, err
	}
	defer d.close()
	p := Join(d.path, name)
	if err := checkRules(p, a.Guard); err != nil {
		return WriteResult{}, err
	}
	sum := sha256.Sum256(data)
	res := WriteResult{Path: p, Hash: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	finish := func(fd int) (WriteResult, error) {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil {
			res.MTime = ts(st.Mtim)
		}
		return res, nil
	}
	var st unix.Stat_t
	err = unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		if !a.Create || !ValidName(name) {
			return res, opErr(CodeNotFound, "")
		}
		unix.Umask(0)
		fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o640)
		if err != nil {
			return res, mapErr(err)
		}
		defer func() { _ = unix.Close(fd) }()
		if err := writeAll(fd, data); err != nil {
			return res, err
		}
		if err := unix.Fsync(fd); err != nil {
			return res, mapErr(err)
		}
		res.Atomic = true
		return finish(fd)
	}
	if err != nil {
		return res, mapErr(err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return res, opErr(CodeSymlink, "")
	case unix.S_IFREG:
	default:
		return res, opErr(CodeNotRegular, "")
	}
	cur, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return res, mapErr(err)
	}
	defer func() { _ = unix.Close(cur) }()
	curHash, err := hashFD(cur)
	if err != nil {
		return res, err
	}
	if curHash != a.ExpectedHash {
		return res, opErr(CodeConflict, "")
	}
	euid := os.Geteuid()
	if (int(st.Uid) == euid || euid == 0) && st.Nlink == 1 && writable(d.fd) {
		r, err := writeAtomic(d, name, cur, &st, data)
		if err == nil {
			res.Atomic = true
			res.MTime = r
			return res, nil
		}
		if !errors.Is(err, errFallback) {
			return res, err
		}
	}
	w, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return res, mapErr(err)
	}
	defer func() { _ = unix.Close(w) }()
	if err := unix.Ftruncate(w, 0); err != nil {
		return res, mapErr(err)
	}
	if err := writeAll(w, data); err != nil {
		return res, err
	}
	if err := unix.Fsync(w); err != nil {
		return res, mapErr(err)
	}
	return finish(w)
}

func writeAtomic(d *dirH, name string, cur int, st *unix.Stat_t, data []byte) (time.Time, error) {
	tmp, tmpName, err := tempFile(d)
	if err != nil {
		return time.Time{}, errFallback
	}
	defer func() { _ = unix.Close(tmp) }()
	cleanup := func(e error) (time.Time, error) {
		if tmpName != "" {
			_ = unix.Unlinkat(d.fd, tmpName, 0)
		}
		return time.Time{}, e
	}
	if err := writeAll(tmp, data); err != nil {
		return cleanup(err)
	}
	if err := unix.Fchown(tmp, int(st.Uid), int(st.Gid)); err != nil {
		return cleanup(errFallback)
	}
	if err := unix.Fchmod(tmp, st.Mode&0o7777); err != nil {
		return cleanup(errFallback)
	}
	if err := copyXattrs(cur, tmp); err != nil {
		return cleanup(err)
	}
	if err := unix.Fsync(tmp); err != nil {
		return cleanup(mapErr(err))
	}
	if err := commit(d, tmp, tmpName, name, true); err != nil {
		return cleanup(err)
	}
	syncDir(d)
	var nst unix.Stat_t
	_ = unix.Fstat(tmp, &nst)
	return ts(nst.Mtim), nil
}

// UploadArgs are the inputs of fs.upload_check and fs.upload.
type UploadArgs struct {
	Dir       string `json:"dir"`
	Name      string `json:"name"`
	Mode      uint32 `json:"mode,omitempty"`
	Overwrite bool   `json:"overwrite,omitempty"`
	Size      int64  `json:"size"` // declared size (space preflight)
	Max       int64  `json:"max"`  // per-file limit, set by the helper
	Guard
}

// UploadCheck is the preflight result.
type UploadCheck struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Free   int64  `json:"free"`
}

// CheckUpload validates an upload before any data is sent.
func CheckUpload(a UploadArgs) (UploadCheck, error) {
	d, err := openDir(a.Dir, true)
	if err != nil {
		return UploadCheck{}, err
	}
	defer d.close()
	return checkUpload(d, a)
}

func checkUpload(d *dirH, a UploadArgs) (UploadCheck, error) {
	if !ValidName(a.Name) {
		return UploadCheck{}, opErr(CodeInvalid, "invalid name")
	}
	p := Join(d.path, a.Name)
	res := UploadCheck{Path: p}
	switch {
	case Blocked(p):
		return res, opErr(CodeBlocked, "")
	case Virtual(p):
		return res, opErr(CodeVirtual, "")
	case a.Max <= 0 || a.Size < 0:
		return res, opErr(CodeInvalid, "")
	case a.Size > a.Max:
		return res, opErr(CodeTooLarge, "")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, a.Name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		res.Exists = true
		switch {
		case !a.Overwrite:
			return res, opErr(CodeExists, "")
		case st.Mode&unix.S_IFMT == unix.S_IFLNK:
			return res, opErr(CodeSymlink, "")
		case st.Mode&unix.S_IFMT == unix.S_IFDIR:
			return res, opErr(CodeIsDir, "")
		case st.Mode&unix.S_IFMT != unix.S_IFREG:
			return res, opErr(CodeNotRegular, "")
		case Sensitive(p) && !a.SensitiveOK:
			return res, opErr(CodeSensitive, "")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return res, mapErr(err)
	}
	if !writable(d.fd) {
		return res, opErr(CodeDenied, "")
	}
	var sf unix.Statfs_t
	if unix.Fstatfs(d.fd, &sf) == nil {
		res.Free = int64(sf.Bavail) * sf.Bsize //nolint:gosec // block counts fit int64
		if a.Size+(1<<20) > res.Free {
			return res, opErr(CodeNoSpace, "")
		}
	}
	return res, nil
}

// UploadResult describes the stored file.
type UploadResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Upload stores the chunked stream in as Dir/Name. Data goes to an anonymous
// temp file in the target directory and is linked into place only after the
// end marker, so aborted uploads leave nothing behind.
func Upload(a UploadArgs, in io.Reader) (UploadResult, error) {
	d, err := openDir(a.Dir, true)
	if err != nil {
		return UploadResult{}, err
	}
	defer d.close()
	chk, err := checkUpload(d, a)
	if err != nil {
		return UploadResult{}, err
	}
	tmp, tmpName, err := tempFile(d)
	if err != nil {
		return UploadResult{}, err
	}
	f := os.NewFile(uintptr(tmp), "upload") //nolint:gosec // fd from openat
	defer func() { _ = f.Close() }()
	fail := func(e error) (UploadResult, error) {
		if tmpName != "" {
			_ = unix.Unlinkat(d.fd, tmpName, 0)
		}
		return UploadResult{}, e
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(in, a.Max+1))
	if err != nil {
		var en unix.Errno
		if errors.As(err, &en) {
			return fail(mapErr(err))
		}
		return fail(opErr(CodeAborted, ""))
	}
	if n > a.Max {
		return fail(opErr(CodeTooLarge, ""))
	}
	mode := a.Mode & 0o777
	if mode == 0 {
		mode = 0o640
	}
	if err := unix.Fchmod(tmp, mode); err != nil {
		return fail(mapErr(err))
	}
	if err := unix.Fsync(tmp); err != nil {
		return fail(mapErr(err))
	}
	if err := commit(d, tmp, tmpName, a.Name, a.Overwrite); err != nil {
		return fail(err)
	}
	syncDir(d)
	return UploadResult{Path: chk.Path, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// --- worker wiring ---

func jsonH[A, R any](fn func(A) (R, error)) worker.Handler {
	return func(raw json.RawMessage) (any, error) {
		var a A
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, opErr(CodeInvalid, "arguments")
		}
		return fn(a)
	}
}

func streamH[A, R any](fn func(A, io.ReadWriter) (R, error)) worker.Handler {
	return func(raw json.RawMessage) (any, error) {
		var a A
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, opErr(CodeInvalid, "arguments")
		}
		data := worker.Data()
		if data == nil {
			return nil, opErr(CodeInvalid, "no data stream")
		}
		defer func() { _ = data.Close() }()
		return fn(a, data)
	}
}

// WorkerHandlers returns the fs.* worker operations.
func WorkerHandlers() map[string]worker.Handler {
	return map[string]worker.Handler{
		"fs.list":         jsonH(List),
		"fs.stat":         jsonH(Stat),
		"fs.create":       jsonH(Create),
		"fs.rename":       jsonH(Rename),
		"fs.chmod":        jsonH(Chmod),
		"fs.chown":        jsonH(Chown),
		"fs.transfer":     jsonH(Transfer),
		"fs.delete":       jsonH(Delete),
		"fs.upload_check": jsonH(CheckUpload),
		"fs.read": streamH(func(a ReadArgs, rw io.ReadWriter) (ReadResult, error) {
			return Read(a, rw)
		}),
		"fs.write": streamH(func(a WriteArgs, rw io.ReadWriter) (WriteResult, error) {
			return Write(a, &rpc.ChunkReader{R: rw})
		}),
		"fs.upload": streamH(func(a UploadArgs, rw io.ReadWriter) (UploadResult, error) {
			return Upload(a, &rpc.ChunkReader{R: rw})
		}),
	}
}
