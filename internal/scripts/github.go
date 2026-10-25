package scripts

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Fetch error codes, returned to the dashboard as data.
const (
	FetchNotFound     = "not_found"
	FetchUnauthorized = "unauthorized"
	FetchRateLimited  = "rate_limited"
	FetchNetwork      = "network"
	FetchTooLarge     = "too_large"
)

// FetchError is a GitHub download problem.
type FetchError struct {
	Code   string
	Detail string
}

func (e *FetchError) Error() string { return "github: " + e.Code + ": " + e.Detail }

// Skipped is a repository file that was not taken over.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"` // name, symlink, size
}

// MaxDownload bounds the compressed tarball.
const MaxDownload = 100 << 20

// GitHub downloads repository snapshots over the REST API.
type GitHub struct {
	// API is https://api.github.com (tests use a local server).
	API  string
	HTTP *http.Client
}

// NewGitHub returns a client for api.github.com.
func NewGitHub() *GitHub {
	return &GitHub{API: "https://api.github.com", HTTP: &http.Client{
		Timeout:   2 * time.Minute,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second},
	}}
}

func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func (g *GitHub) get(ctx context.Context, path, token, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.API+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "daemonica")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, &FetchError{Code: FetchNetwork, Detail: err.Error()}
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnprocessableEntity:
		// Private repositories also answer 404 without a token.
		return nil, &FetchError{Code: FetchNotFound, Detail: resp.Status}
	case resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0"):
		return nil, &FetchError{Code: FetchRateLimited, Detail: resp.Status}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &FetchError{Code: FetchUnauthorized, Detail: resp.Status}
	}
	return nil, &FetchError{Code: FetchNetwork, Detail: resp.Status}
}

// Resolve returns the commit a ref ("" for the default branch) points to.
func (g *GitHub) Resolve(ctx context.Context, repo, ref, token string) (Commit, error) {
	if ref == "" {
		ref = "HEAD"
	}
	resp, err := g.get(ctx, "/repos/"+repo+"/commits/"+escapeRef(ref), token, "application/vnd.github+json")
	if err != nil {
		return Commit{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name string    `json:"name"`
				Date time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return Commit{}, &FetchError{Code: FetchNetwork, Detail: err.Error()}
	}
	if !ValidCommit(body.SHA) {
		return Commit{}, &FetchError{Code: FetchNetwork, Detail: "bad sha"}
	}
	msg, _, _ := strings.Cut(body.Commit.Message, "\n")
	return Commit{SHA: body.SHA, Message: truncate(msg, 200), Author: truncate(body.Commit.Author.Name, 100), Date: body.Commit.Author.Date.UTC()}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Tree downloads the files of repo at sha below subdir.
func (g *GitHub) Tree(ctx context.Context, repo, sha, subdir, token string) (Tree, []Skipped, error) {
	if !ValidCommit(sha) {
		return nil, nil, ErrInvalid
	}
	resp, err := g.get(ctx, "/repos/"+repo+"/tarball/"+sha, token, "application/vnd.github+json")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	t, skipped, err := ParseTarball(io.LimitReader(resp.Body, MaxDownload+1), subdir)
	var fe *FetchError
	if err != nil && !errors.As(err, &fe) && !errors.Is(err, ErrTooLarge) {
		err = &FetchError{Code: FetchNetwork, Detail: err.Error()}
	}
	if errors.Is(err, ErrTooLarge) {
		err = &FetchError{Code: FetchTooLarge, Detail: err.Error()}
	}
	return t, skipped, err
}

// ParseTarball reads a GitHub tarball (one top-level directory) and keeps
// the regular files below subdir. Hidden files are left out silently;
// symlinks, unusable names and large files are reported as skipped.
func ParseTarball(r io.Reader, subdir string) (Tree, []Skipped, error) {
	cr := &countingReader{r: r}
	zr, err := gzip.NewReader(cr)
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(zr)
	t := Tree{}
	skipped := []Skipped{}
	total := 0
	prefix := ""
	if subdir != "" {
		prefix = subdir + "/"
	}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if cr.n > MaxDownload {
			return nil, nil, fmt.Errorf("%w: download", ErrTooLarge)
		}
		// Strip the "<owner>-<repo>-<sha>/" directory.
		_, name, ok := strings.Cut(h.Name, "/")
		if !ok || name == "" {
			continue
		}
		rel, ok := strings.CutPrefix(name, prefix)
		if !ok || rel == "" {
			continue
		}
		rel = strings.TrimSuffix(rel, "/")
		if hidden(rel) {
			continue
		}
		switch h.Typeflag {
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			skipped = append(skipped, Skipped{Path: rel, Reason: "symlink"})
			continue
		default:
			continue
		}
		if !ValidPath(rel) {
			skipped = append(skipped, Skipped{Path: truncate(rel, 512), Reason: "name"})
			continue
		}
		if h.Size > MaxFileSize {
			skipped = append(skipped, Skipped{Path: rel, Reason: "size"})
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
		if err != nil {
			return nil, nil, err
		}
		total += len(b)
		if len(t) >= MaxFiles || total > MaxTreeSize {
			return nil, nil, fmt.Errorf("%w: more than %d files or %d MiB", ErrTooLarge, MaxFiles, MaxTreeSize>>20)
		}
		t[rel] = Entry{Data: b, Exec: h.Mode&0o111 != 0}
	}
	if cr.n > MaxDownload {
		return nil, nil, fmt.Errorf("%w: download", ErrTooLarge)
	}
	if len(skipped) > 200 {
		skipped = skipped[:200]
	}
	return t, skipped, nil
}

// hidden reports whether a path has a component starting with a dot
// (.github, .gitignore, …).
func hidden(p string) bool {
	for c := range strings.SplitSeq(p, "/") {
		if strings.HasPrefix(c, ".") {
			return true
		}
	}
	return false
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
