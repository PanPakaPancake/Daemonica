package netcfg

import (
	"fmt"
	"strings"
)

// UnifiedDiff renders a line diff of a and b with three lines of context.
// Inputs are configuration files (small); beyond 2000 lines each the diff
// falls back to "replace everything".
func UnifiedDiff(path string, a, b *string) string {
	var x, y []string
	if a != nil {
		x = splitLines(*a)
	}
	if b != nil {
		y = splitLines(*b)
	}
	var sb strings.Builder
	from, to := "a"+path, "b"+path
	if a == nil {
		from = "/dev/null"
	}
	if b == nil {
		to = "/dev/null"
	}
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", from, to)
	ops := lineOps(x, y)
	const ctx = 3
	for i := 0; i < len(ops); {
		if ops[i].op == ' ' {
			i++
			continue
		}
		start := max(0, i-ctx)
		end := i
		// extend the hunk while changes are within 2*ctx lines of each other
		for j := i; j < len(ops); j++ {
			if ops[j].op != ' ' {
				end = j
			} else if j-end > 2*ctx {
				break
			}
		}
		end = min(len(ops)-1, end+ctx)
		for _, o := range ops[start : end+1] {
			sb.WriteByte(o.op)
			sb.WriteString(o.line)
			sb.WriteByte('\n')
		}
		sb.WriteString("@@\n")
		i = end + 1
	}
	return strings.TrimSuffix(sb.String(), "@@\n")
}

type lineOp struct {
	op   byte
	line string
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func lineOps(x, y []string) []lineOp {
	if len(x) > 2000 || len(y) > 2000 {
		var out []lineOp
		for _, l := range x {
			out = append(out, lineOp{'-', l})
		}
		for _, l := range y {
			out = append(out, lineOp{'+', l})
		}
		return out
	}
	// LCS table
	n, m := len(x), len(y)
	t := make([][]int, n+1)
	for i := range t {
		t[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	var out []lineOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			out = append(out, lineOp{' ', x[i]})
			i++
			j++
		case t[i+1][j] >= t[i][j+1]:
			out = append(out, lineOp{'-', x[i]})
			i++
		default:
			out = append(out, lineOp{'+', y[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, lineOp{'-', x[i]})
	}
	for ; j < m; j++ {
		out = append(out, lineOp{'+', y[j]})
	}
	return out
}
