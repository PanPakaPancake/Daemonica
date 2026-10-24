package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// Filter selects audit events. Empty fields match everything.
type Filter struct {
	ActionPrefix string `json:"action,omitempty"`
	Result       string `json:"result,omitempty"`
	Actor        string `json:"actor,omitempty"`  // account name or id (exact)
	Text         string `json:"text,omitempty"`   // case-insensitive substring of target/reason/source IP
	Since        string `json:"since,omitempty"`  // RFC 3339, inclusive
	Until        string `json:"until,omitempty"`  // RFC 3339, exclusive
	Before       string `json:"before,omitempty"` // cursor: only events with event_id < Before
	Limit        int    `json:"limit,omitempty"`
}

// MaxQueryLimit bounds one page.
const MaxQueryLimit = 500

func (f Filter) match(e *Event) bool {
	switch {
	case f.ActionPrefix != "" && !strings.HasPrefix(e.Action, f.ActionPrefix):
		return false
	case f.Result != "" && e.Result != f.Result:
		return false
	case f.Actor != "" && e.Actor.Name != f.Actor && e.Actor.AccountID != f.Actor:
		return false
	case f.Since != "" && e.TS < f.Since:
		return false
	case f.Until != "" && e.TS >= f.Until:
		return false
	case f.Before != "" && e.EventID >= f.Before:
		return false
	}
	if f.Text != "" {
		t := strings.ToLower(f.Text)
		if !strings.Contains(strings.ToLower(e.Target+" "+e.Reason+" "+e.SourceIP), t) {
			return false
		}
	}
	return true
}

// Page is one query result, newest first. Next is the cursor for older events.
type Page struct {
	Events []Event `json:"events"`
	Next   string  `json:"next,omitempty"`
}

// Query scans r (JSON Lines, oldest first) and returns the newest Limit
// matching events. Unparseable lines are skipped (Verify reports them).
func Query(r io.Reader, f Filter) (Page, error) {
	if f.Limit <= 0 || f.Limit > MaxQueryLimit {
		f.Limit = 100
	}
	ring := make([]Event, 0, f.Limit+1)
	more := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil || !f.match(&e) {
			continue
		}
		ring = append(ring, e)
		if len(ring) > f.Limit {
			ring = ring[1:]
			more = true
		}
	}
	if err := sc.Err(); err != nil {
		return Page{}, err
	}
	out := make([]Event, len(ring))
	for i := range ring {
		out[i] = ring[len(ring)-1-i]
	}
	p := Page{Events: out}
	if more && len(out) > 0 {
		p.Next = out[len(out)-1].EventID
	}
	return p, nil
}
