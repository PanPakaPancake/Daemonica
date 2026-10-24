package journal

import (
	"strings"
	"testing"
	"time"
)

func TestArgsValidation(t *testing.T) {
	p := 3
	q := Query{Unit: "ssh.service", Priority: &p, Boot: "-1", Grep: "fail (x)", Lines: 99999,
		Since: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	args, err := q.Args()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--unit=ssh.service", "--priority=3", "--boot=-1", `--grep=fail \(x\)`, "--lines=5000", "--since=2026-10-24 12:00:00", "--output=json"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			t.Errorf("positional argument %q (option injection risk)", a)
		}
	}
	bad := []Query{
		{Unit: "--help"}, {Unit: "x.service; id"}, {Unit: "a\nb.service"},
		{Boot: "1; rm"}, {Boot: "--all"}, {Grep: "a\nb"}, {Grep: strings.Repeat("a", 201)},
		{After: "x y"}, {After: "--flag"}, {Identifier: "-x"}, {Identifier: "a b"},
		{Priority: func() *int { v := 8; return &v }()},
	}
	for _, b := range bad {
		if _, err := b.Args(); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
}

func TestParseSanitisesAndCaps(t *testing.T) {
	data := `{"__CURSOR":"s=1;i=1","__REALTIME_TIMESTAMP":"1761307200000000","PRIORITY":"3","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","_PID":"42","MESSAGE":"Failed password\u001b[31m for root\n"}
{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1761307201000000","MESSAGE":[104,105,7,10]}
not json
{"__CURSOR":"s=1;i=3","MESSAGE":"third","PRIORITY":"99"}
`
	r := Parse([]byte(data), 2)
	if len(r.Entries) != 2 || !r.Truncated || r.Cursor != "s=1;i=2" {
		t.Fatalf("parse result %+v", r)
	}
	e := r.Entries[0]
	if e.Priority != 3 || e.Unit != "ssh.service" || e.PID != 42 || strings.ContainsAny(e.Message, "\x1b\n") {
		t.Fatalf("entry %+v", e)
	}
	if r.Entries[1].Message != "hi" {
		t.Fatalf("byte-array message %q", r.Entries[1].Message)
	}
	all := Parse([]byte(data), 10)
	if all.Entries[2].Priority != 6 {
		t.Fatal("out-of-range priority must default to info")
	}
}
