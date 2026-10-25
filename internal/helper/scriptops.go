package helper

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PanPakaPancake/daemonica/internal/jobs"
	"github.com/PanPakaPancake/daemonica/internal/policy"
	"github.com/PanPakaPancake/daemonica/internal/rpc"
	"github.com/PanPakaPancake/daemonica/internal/scripts"
)

// ScriptOps exposes the script library (DEC-030). Reading is open to all
// roles like the job list; fetching from GitHub needs the job write rule,
// and every change of the library needs admin + step-up because root jobs
// may run its files.
type ScriptOps struct {
	L *scripts.Library
	// Jobs lists the managed jobs (for "used by").
	Jobs func() ([]jobs.Job, error)
}

// ScriptList is the scripts.list result.
type ScriptList struct {
	Root    string               `json:"root"`
	Sources []scripts.SourceView `json:"sources"`
	Files   []scripts.File       `json:"files"`
}

// ScriptContent is the scripts.read result.
type ScriptContent struct {
	Text    bool   `json:"text"`
	Content string `json:"content,omitempty"`
	Hash    string `json:"hash"`
	Size    int    `json:"size"`
}

// ScriptCandidate is the scripts.preview and scripts.check result. Input
// and download problems come back as data (the web layer only passes error
// codes).
type ScriptCandidate struct {
	Candidate *scripts.Candidate `json:"candidate,omitempty"`
	Spec      *scripts.Spec      `json:"spec,omitempty"`
	Error     *FieldError        `json:"error,omitempty"`
}

type scriptRef struct {
	Source string `json:"source"`
	Path   string `json:"path"`
}

type scriptSave struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Exec    bool   `json:"exec"`
	Hash    string `json:"hash"`
}

type scriptAdd struct {
	Spec   scripts.Spec `json:"spec"`
	Commit string       `json:"commit"`
}

type scriptUpdate struct {
	ID     string `json:"id"`
	Commit string `json:"commit"`
}

// usedBy maps job paths (program, script) to the jobs that use them.
func (o *ScriptOps) usedBy() map[string][]string {
	m := map[string][]string{}
	if o.Jobs == nil {
		return m
	}
	list, _ := o.Jobs()
	for _, j := range list {
		for _, p := range []string{j.Program, j.Script} {
			if p != "" {
				m[p] = append(m[p], j.ID)
			}
		}
	}
	return m
}

// usersBelow lists the jobs using a file below dir.
func usersBelow(used map[string][]string, dir string) []string {
	var out []string
	for p, ids := range used {
		if strings.HasPrefix(p, dir+"/") {
			out = append(out, ids...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func scriptErr(err error) error {
	var fe *scripts.FetchError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, scripts.ErrNotFound):
		return Errf(rpc.CodeNotFound, "")
	case errors.Is(err, scripts.ErrExists):
		return Errf(rpc.CodeConflict, "exists")
	case errors.Is(err, scripts.ErrStale):
		return Errf(rpc.CodeConflict, "stale")
	case errors.Is(err, scripts.ErrInvalid), errors.Is(err, scripts.ErrTooLarge):
		return Errf(rpc.CodeValidation, "%v", err)
	case errors.As(err, &fe):
		return Errf(rpc.CodeUnavailable, "%s", fe.Code)
	}
	return err
}

func fetchField(err error) (*FieldError, error) {
	var fe *scripts.FetchError
	if errors.As(err, &fe) {
		return &FieldError{Field: "fetch", Code: fe.Code}, nil
	}
	if errors.Is(err, scripts.ErrTooLarge) {
		return &FieldError{Field: "fetch", Code: scripts.FetchTooLarge}, nil
	}
	return nil, err
}

// suggestID derives a free source id from the repository name.
func (o *ScriptOps) suggestID(repo string) string {
	_, name, _ := strings.Cut(repo, "/")
	base := strings.Trim(strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return '-'
	}, name), "-")
	if len(base) > 30 {
		base = strings.Trim(base[:30], "-")
	}
	if base == "" || base == scripts.LocalID {
		base = "scripts"
	}
	srcs, _ := o.L.Sources()
	taken := func(id string) bool {
		return slices.ContainsFunc(srcs, func(s scripts.Source) bool { return s.ID == id })
	}
	id := base
	for i := 2; taken(id); i++ {
		id = base + "-" + strconv.Itoa(i)
	}
	return id
}

func scriptTarget(c Call) string {
	var p struct {
		ID   string       `json:"id"`
		Name string       `json:"name"`
		Spec scripts.Spec `json:"spec"`
	}
	_ = json.Unmarshal(c.Params, &p)
	switch {
	case p.Name != "":
		return "script:local/" + p.Name
	case p.Spec.ID != "":
		return "scripts:" + p.Spec.ID
	}
	return "scripts:" + p.ID
}

// Register installs the scripts.* operations.
func (o *ScriptOps) Register(ops map[string]*Op) {
	gh := o.L.GitHub

	Register(ops, &Op{Name: "scripts.list", Action: policy.ActJobsRead, NoAudit: true, Timeout: 30 * time.Second,
		Handle: func(_ context.Context, _ Call) (any, error) {
			srcs, err := o.L.Sources()
			if err != nil {
				return nil, err
			}
			files, err := o.L.Files()
			if err != nil {
				return nil, err
			}
			used := o.usedBy()
			for i := range files {
				files[i].UsedBy = used[files[i].Abs]
			}
			res := ScriptList{Root: o.L.Root, Sources: []scripts.SourceView{}, Files: files}
			for _, s := range srcs {
				res.Sources = append(res.Sources, s.View())
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "scripts.read", Action: policy.ActJobsRead, NoAudit: true,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p scriptRef
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			b, hash, err := o.L.Read(p.Source, p.Path)
			if errors.Is(err, scripts.ErrTooLarge) {
				return ScriptContent{Size: -1}, nil
			}
			if err != nil {
				return nil, scriptErr(err)
			}
			res := ScriptContent{Hash: hash, Size: len(b), Text: scripts.IsText(b)}
			if res.Text {
				res.Content = string(b)
			}
			return res, nil
		}})

	Register(ops, &Op{Name: "scripts.preview", Action: policy.ActJobsWrite, NoAudit: true, Timeout: 3 * time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p struct {
				Spec scripts.Spec `json:"spec"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			spec, field := p.Spec.Normalize()
			if field != "" {
				return ScriptCandidate{Error: &FieldError{Field: field, Code: jobs.CodeInvalid}}, nil
			}
			if spec.ID == "" {
				spec.ID = o.suggestID(spec.Repo)
			}
			commit, err := gh.Resolve(ctx, spec.Repo, spec.Ref, spec.Token)
			if err != nil {
				fe, err := fetchField(err)
				return ScriptCandidate{Error: fe}, err
			}
			t, skipped, err := gh.Tree(ctx, spec.Repo, commit.SHA, spec.Subdir, spec.Token)
			if err != nil {
				fe, err := fetchField(err)
				return ScriptCandidate{Error: fe}, err
			}
			spec.Token = ""
			return ScriptCandidate{Spec: &spec, Candidate: &scripts.Candidate{Commit: commit, Files: len(t), Size: t.Size(),
				Changes: scripts.Compare(nil, t), Skipped: skipped}}, nil
		}})

	Register(ops, &Op{Name: "scripts.check", Action: policy.ActJobsWrite, NoAudit: true, Timeout: 3 * time.Minute,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p jobIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			src, err := o.L.Source(p.ID)
			if err != nil {
				return nil, scriptErr(err)
			}
			ref := src.Ref
			if scripts.ValidCommit(ref) {
				ref = src.Commit.SHA // pinned to a commit: nothing newer to offer
			}
			commit, err := gh.Resolve(ctx, src.Repo, ref, src.Token)
			if err != nil {
				fe, err := fetchField(err)
				return ScriptCandidate{Error: fe}, err
			}
			cand := &scripts.Candidate{Commit: commit, Changes: []scripts.Change{}, Skipped: []scripts.Skipped{}, Current: commit.SHA == src.Commit.SHA}
			if cand.Current {
				cur, err := o.L.ReadTree(src.ID)
				if err != nil {
					return nil, err
				}
				cand.Files, cand.Size = len(cur), cur.Size()
				return ScriptCandidate{Candidate: cand}, nil
			}
			t, skipped, err := gh.Tree(ctx, src.Repo, commit.SHA, src.Subdir, src.Token)
			if err != nil {
				fe, err := fetchField(err)
				return ScriptCandidate{Error: fe}, err
			}
			cur, err := o.L.ReadTree(src.ID)
			if err != nil {
				return nil, err
			}
			cand.Files, cand.Size, cand.Skipped = len(t), t.Size(), skipped
			cand.Changes = scripts.Compare(cur, t)
			used := o.usedBy()
			for i, ch := range cand.Changes {
				cand.Changes[i].UsedBy = used[o.L.Abs(src.ID, ch.Path)]
			}
			return ScriptCandidate{Candidate: cand}, nil
		}})

	Register(ops, &Op{Name: "scripts.add", Action: policy.ActJobsWriteRoot, Timeout: 3 * time.Minute, AuditTarget: scriptTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p scriptAdd
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			spec, field := p.Spec.Normalize()
			if field != "" || !scripts.ValidID(spec.ID) || !scripts.ValidCommit(p.Commit) {
				return nil, Errf(rpc.CodeValidation, "invalid source")
			}
			// The reviewed commit, not whatever the ref points to now.
			commit, err := gh.Resolve(ctx, spec.Repo, p.Commit, spec.Token)
			if err != nil {
				return nil, scriptErr(err)
			}
			t, _, err := gh.Tree(ctx, spec.Repo, commit.SHA, spec.Subdir, spec.Token)
			if err != nil {
				return nil, scriptErr(err)
			}
			src, err := o.L.Add(spec, commit, t, c.Subject.AccountID)
			if err != nil {
				return nil, scriptErr(err)
			}
			c.AuditKV["repo"] = spec.Repo
			c.AuditKV["commit"] = commit.SHA
			c.AuditKV["files"] = strconv.Itoa(len(t))
			if spec.Subdir != "" {
				c.AuditKV["subdir"] = spec.Subdir
			}
			return src.View(), nil
		}})

	Register(ops, &Op{Name: "scripts.update", Action: policy.ActJobsWriteRoot, Timeout: 3 * time.Minute, AuditTarget: scriptTarget,
		Handle: func(ctx context.Context, c Call) (any, error) {
			var p scriptUpdate
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !scripts.ValidCommit(p.Commit) {
				return nil, Errf(rpc.CodeValidation, "commit")
			}
			src, err := o.L.Source(p.ID)
			if err != nil {
				return nil, scriptErr(err)
			}
			commit, err := gh.Resolve(ctx, src.Repo, p.Commit, src.Token)
			if err != nil {
				return nil, scriptErr(err)
			}
			t, _, err := gh.Tree(ctx, src.Repo, commit.SHA, src.Subdir, src.Token)
			if err != nil {
				return nil, scriptErr(err)
			}
			from := src.Commit.SHA
			src, err = o.L.Update(p.ID, commit, t, c.Subject.AccountID)
			if err != nil {
				return nil, scriptErr(err)
			}
			c.AuditKV["repo"] = src.Repo
			c.AuditKV["from"] = from
			c.AuditKV["commit"] = commit.SHA
			c.AuditKV["files"] = strconv.Itoa(len(t))
			return src.View(), nil
		}})

	Register(ops, &Op{Name: "scripts.remove", Action: policy.ActJobsWriteRoot, Timeout: 30 * time.Second, AuditTarget: scriptTarget,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p jobIDParams
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if !scripts.ValidID(p.ID) {
				return nil, Errf(rpc.CodeNotFound, "")
			}
			if u := usersBelow(o.usedBy(), o.L.SourceDir(p.ID)); len(u) > 0 {
				return nil, Errf(rpc.CodeConflict, "in use by %s", strings.Join(u, ", "))
			}
			return nil, scriptErr(o.L.RemoveSource(p.ID))
		}})

	Register(ops, &Op{Name: "scripts.save", Action: policy.ActJobsWriteRoot, Timeout: 30 * time.Second, AuditTarget: scriptTarget,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p scriptSave
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			hash, err := o.L.SaveLocal(p.Name, []byte(p.Content), p.Exec, p.Hash)
			if err != nil {
				return nil, scriptErr(err)
			}
			c.AuditKV["sha256"] = hash
			c.AuditKV["size"] = strconv.Itoa(len(p.Content))
			c.AuditKV["exec"] = strconv.FormatBool(p.Exec)
			if p.Hash == "" {
				c.AuditKV["created"] = "true"
			}
			return map[string]string{"hash": hash, "abs": o.L.Abs(scripts.LocalID, p.Name)}, nil
		}})

	Register(ops, &Op{Name: "scripts.delete", Action: policy.ActJobsWriteRoot, Timeout: 30 * time.Second, AuditTarget: scriptTarget,
		Handle: func(_ context.Context, c Call) (any, error) {
			var p struct {
				Name string `json:"name"`
			}
			if err := decode(c, &p); err != nil {
				return nil, err
			}
			if u := o.usedBy()[o.L.Abs(scripts.LocalID, p.Name)]; len(u) > 0 {
				return nil, Errf(rpc.CodeConflict, "in use by %s", strings.Join(u, ", "))
			}
			return nil, scriptErr(o.L.DeleteLocal(p.Name))
		}})
}
