package planner

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeHandler struct {
	mu        sync.Mutex
	value     string
	prev      string
	failApply bool
	rollbacks int
}

func (f *fakeHandler) Kind() string { return "test" }
func (f *fakeHandler) Apply(_ context.Context, p json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var v string
	_ = json.Unmarshal(p, &v)
	f.prev, f.value = f.value, v
	if f.failApply {
		return errors.New("boom")
	}
	return nil
}
func (f *fakeHandler) Rollback(_ context.Context, _ json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.value = f.prev
	f.rollbacks++
	return nil
}
func (f *fakeHandler) get() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.value, f.rollbacks
}

func TestAutoRollbackWithoutConfirm(t *testing.T) {
	m, err := New(t.TempDir(), 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHandler{value: "old"}
	m.Register(h)
	c, _ := m.Plan("test", "acc", "set value", "-old\n+new", "high", json.RawMessage(`"new"`))
	if _, err := m.Apply(context.Background(), c.ID, "acc"); err != nil {
		t.Fatal(err)
	}
	if v, _ := h.get(); v != "new" {
		t.Fatal("not applied")
	}
	time.Sleep(200 * time.Millisecond)
	if v, n := h.get(); v != "old" || n != 1 {
		t.Fatalf("not rolled back: %q %d", v, n)
	}
	got, _ := m.Get(c.ID)
	if got.State != StateRolledBack {
		t.Fatalf("state %s", got.State)
	}
	if _, err := m.Confirm(c.ID, "acc"); err == nil {
		t.Fatal("confirm after rollback must fail")
	}
}

func TestConfirmKeepsChange(t *testing.T) {
	m, _ := New(t.TempDir(), 100*time.Millisecond)
	h := &fakeHandler{value: "old"}
	m.Register(h)
	c, _ := m.Plan("test", "acc", "", "", "low", json.RawMessage(`"new"`))
	_, _ = m.Apply(context.Background(), c.ID, "acc")
	if _, err := m.Confirm(c.ID, "other"); !errors.Is(err, ErrNotOwner) {
		t.Fatal("foreign confirm accepted")
	}
	if _, err := m.Confirm(c.ID, "acc"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if v, n := h.get(); v != "new" || n != 0 {
		t.Fatalf("confirmed change was rolled back: %q %d", v, n)
	}
}

func TestApplyFailureRollsBack(t *testing.T) {
	m, _ := New(t.TempDir(), time.Second)
	h := &fakeHandler{value: "old", failApply: true}
	m.Register(h)
	c, _ := m.Plan("test", "acc", "", "", "low", json.RawMessage(`"new"`))
	if _, err := m.Apply(context.Background(), c.ID, "acc"); err == nil {
		t.Fatal("expected failure")
	}
	if v, _ := h.get(); v != "old" {
		t.Fatal("partial apply not reverted")
	}
}

func TestRecoverAfterCrash(t *testing.T) {
	dir := t.TempDir()
	m1, _ := New(dir, time.Hour)
	h1 := &fakeHandler{value: "old"}
	m1.Register(h1)
	c, _ := m1.Plan("test", "acc", "", "", "high", json.RawMessage(`"new"`))
	_, _ = m1.Apply(context.Background(), c.ID, "acc")
	// Simulate crash: new manager over the same journal.
	m2, _ := New(dir, time.Hour)
	h2 := &fakeHandler{value: "new", prev: "old"}
	m2.Register(h2)
	if errs := m2.Recover(context.Background()); len(errs) != 0 {
		t.Fatal(errs)
	}
	if v, n := h2.get(); v != "old" || n != 1 {
		t.Fatalf("recovery did not roll back: %q %d", v, n)
	}
	if errs := m2.Recover(context.Background()); len(errs) != 0 {
		t.Fatal("second recover should be a no-op")
	}
	if _, n := h2.get(); n != 1 {
		t.Fatal("journal not cleared")
	}
}

func TestOnePendingPerKind(t *testing.T) {
	m, _ := New(t.TempDir(), time.Hour)
	m.Register(&fakeHandler{})
	a, _ := m.Plan("test", "acc", "", "", "low", json.RawMessage(`"a"`))
	b, _ := m.Plan("test", "acc", "", "", "low", json.RawMessage(`"b"`))
	_, _ = m.Apply(context.Background(), a.ID, "acc")
	if _, err := m.Apply(context.Background(), b.ID, "acc"); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
}
