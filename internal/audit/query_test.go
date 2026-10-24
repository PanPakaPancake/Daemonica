package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQueryFilterAndPaging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		res := ResultOK
		if i%2 == 1 {
			res = ResultDenied
		}
		if _, err := l.Append(Event{Action: "accounts.invite", Result: res, Target: "account:x", Actor: Actor{Name: "Pancake"}}); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = l.Append(Event{Action: "auth.finish_login", Result: ResultOK, SourceIP: "203.0.113.9"})
	_ = l.Close()

	read := func(f Filter) Page {
		fh, _ := os.Open(path)
		defer func() { _ = fh.Close() }()
		p, err := Query(fh, f)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read(Filter{ActionPrefix: "accounts.", Limit: 3})
	if len(p.Events) != 3 || p.Next == "" || p.Events[0].TS < p.Events[2].TS {
		t.Fatalf("page 1 wrong: %+v", p)
	}
	p2 := read(Filter{ActionPrefix: "accounts.", Limit: 3, Before: p.Next})
	p3 := read(Filter{ActionPrefix: "accounts.", Limit: 3, Before: p2.Next})
	if len(p2.Events) != 3 || len(p3.Events) != 1 || p3.Next != "" {
		t.Fatalf("paging wrong: %d %d %q", len(p2.Events), len(p3.Events), p3.Next)
	}
	if n := len(read(Filter{Result: ResultDenied}).Events); n != 3 {
		t.Fatalf("result filter: %d", n)
	}
	if n := len(read(Filter{Text: "203.0.113"}).Events); n != 1 {
		t.Fatalf("text filter: %d", n)
	}
	if n := len(read(Filter{Actor: "Pancake"}).Events); n != 7 {
		t.Fatalf("actor filter: %d", n)
	}
}
