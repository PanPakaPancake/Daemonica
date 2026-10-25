package scripts

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/PanPakaPancake/daemonica/internal/netcfg"
)

// Change is one file difference between two trees.
type Change struct {
	Path   string `json:"path"`
	Status string `json:"status"` // added, removed, modified, mode
	Exec   bool   `json:"exec"`
	Binary bool   `json:"binary,omitempty"`
	// Diff is a unified diff; empty with Omitted when the budget ran out.
	Diff    string   `json:"diff,omitempty"`
	Omitted bool     `json:"omitted,omitempty"`
	UsedBy  []string `json:"used_by,omitempty"`
}

// Compare lists the changes from old to cur, with unified diffs of text
// files until MaxDiffBytes of diff text are used.
func Compare(old, cur Tree) []Change {
	paths := make([]string, 0, len(old)+len(cur))
	for p := range old {
		paths = append(paths, p)
	}
	for p := range cur {
		if _, ok := old[p]; !ok {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	budget := MaxDiffBytes
	out := []Change{}
	for _, p := range paths {
		a, inOld := old[p]
		b, inNew := cur[p]
		c := Change{Path: p, Exec: b.Exec}
		switch {
		case !inOld:
			c.Status = "added"
		case !inNew:
			c.Status, c.Exec = "removed", a.Exec
		case string(a.Data) != string(b.Data):
			c.Status = "modified"
		case a.Exec != b.Exec:
			c.Status = "mode"
		default:
			continue
		}
		if c.Status != "mode" {
			var x, y *string
			if inOld {
				x = textOf(a.Data, &c.Binary)
			}
			if inNew {
				y = textOf(b.Data, &c.Binary)
			}
			if !c.Binary {
				d := netcfg.UnifiedDiff("/"+p, x, y)
				enc, _ := json.Marshal(d)
				if len(enc) <= budget {
					c.Diff = d
					budget -= len(enc)
				} else {
					c.Omitted = true
				}
			}
		}
		out = append(out, c)
	}
	return out
}

func textOf(b []byte, binary *bool) *string {
	if !IsText(b) {
		*binary = true
		return nil
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return &s
}
