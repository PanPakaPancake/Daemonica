// Package disks reads block devices and mounts and edits /etc/fstab
// (SPEC §7.8 M1.7, DEC-032). No partitioning or formatting (non-goal).
package disks

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/execx"
)

// Run runs a program (netcfg.ExecRunner in production).
type Run func(ctx context.Context, timeout time.Duration, path string, args ...string) (execx.Result, error)

// Programs.
var (
	Lsblk   = "/usr/bin/lsblk"
	Findmnt = "/usr/bin/findmnt"
)

// Block is a block device (lsblk).
type Block struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Type        string   `json:"type"` // disk, part, lvm, crypt, raid1, loop, rom …
	Size        uint64   `json:"size"`
	FSType      string   `json:"fstype,omitempty"`
	FSVersion   string   `json:"fsver,omitempty"`
	UUID        string   `json:"uuid,omitempty"`
	PartUUID    string   `json:"partuuid,omitempty"`
	Label       string   `json:"label,omitempty"`
	Mountpoints []string `json:"mountpoints"`
	Model       string   `json:"model,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	ReadOnly    bool     `json:"ro"`
	Removable   bool     `json:"rm"`
	Rotational  bool     `json:"rota"`
	Transport   string   `json:"tran,omitempty"`
	FSUsed      uint64   `json:"fsused,omitempty"`
	FSAvail     uint64   `json:"fsavail,omitempty"`
	Children    []Block  `json:"children,omitempty"`
}

// LsblkColumns are the columns requested from lsblk.
const LsblkColumns = "NAME,PATH,TYPE,SIZE,FSTYPE,FSVER,UUID,PARTUUID,LABEL,MOUNTPOINTS,MODEL,SERIAL,RO,RM,ROTA,TRAN,FSUSED,FSAVAIL"

// flex decodes lsblk values that are numbers, strings, booleans or null
// depending on the util-linux version.
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case string(b) == "null":
		*f = ""
	case len(b) > 0 && b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flex(s)
	default:
		*f = flex(b)
	}
	return nil
}

func (f flex) str() string { return clip(strings.TrimSpace(string(f)), 200) }

func (f flex) num() uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(string(f)), 10, 64)
	return n
}

func (f flex) bool() bool { return f == "true" || f == "1" }

type rawBlock struct {
	Name        flex       `json:"name"`
	Path        flex       `json:"path"`
	Type        flex       `json:"type"`
	Size        flex       `json:"size"`
	FSType      flex       `json:"fstype"`
	FSVer       flex       `json:"fsver"`
	UUID        flex       `json:"uuid"`
	PartUUID    flex       `json:"partuuid"`
	Label       flex       `json:"label"`
	Mountpoint  flex       `json:"mountpoint"`
	Mountpoints []*string  `json:"mountpoints"`
	Model       flex       `json:"model"`
	Serial      flex       `json:"serial"`
	RO          flex       `json:"ro"`
	RM          flex       `json:"rm"`
	Rota        flex       `json:"rota"`
	Tran        flex       `json:"tran"`
	FSUsed      flex       `json:"fsused"`
	FSAvail     flex       `json:"fsavail"`
	Children    []rawBlock `json:"children"`
}

func (r rawBlock) block() Block {
	b := Block{Name: r.Name.str(), Path: r.Path.str(), Type: r.Type.str(), Size: r.Size.num(), FSType: r.FSType.str(), FSVersion: r.FSVer.str(),
		UUID: r.UUID.str(), PartUUID: r.PartUUID.str(), Label: r.Label.str(), Model: r.Model.str(), Serial: r.Serial.str(),
		ReadOnly: r.RO.bool(), Removable: r.RM.bool(), Rotational: r.Rota.bool(), Transport: r.Tran.str(),
		FSUsed: r.FSUsed.num(), FSAvail: r.FSAvail.num(), Mountpoints: []string{}}
	for _, m := range r.Mountpoints {
		if m != nil && *m != "" {
			b.Mountpoints = append(b.Mountpoints, clip(*m, 4096))
		}
	}
	if len(b.Mountpoints) == 0 && r.Mountpoint != "" {
		b.Mountpoints = append(b.Mountpoints, r.Mountpoint.str())
	}
	for _, c := range r.Children {
		b.Children = append(b.Children, c.block())
	}
	return b
}

// ParseLsblk parses lsblk -J -b output.
func ParseLsblk(data []byte) ([]Block, error) {
	var raw struct {
		Blockdevices []rawBlock `json:"blockdevices"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := []Block{}
	for _, r := range raw.Blockdevices {
		out = append(out, r.block())
	}
	return out, nil
}

// Blocks runs lsblk.
func Blocks(ctx context.Context, run Run) ([]Block, error) {
	res, err := run(ctx, 30*time.Second, Lsblk, "-J", "-b", "-o", LsblkColumns)
	if err != nil {
		return nil, err
	}
	return ParseLsblk(res.Stdout)
}

// Flatten returns all devices of the tree (depth first).
func Flatten(bs []Block) []Block {
	var out []Block
	for _, b := range bs {
		c := b
		c.Children = nil
		out = append(out, c)
		out = append(out, Flatten(b.Children)...)
	}
	return out
}

// clip removes control characters and limits s to max bytes.
func clip(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}
