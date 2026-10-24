// Package sshkeys parses and validates OpenSSH authorized_keys entries
// (SPEC §7.3). Only the public key blob is inspected; private keys are never
// handled. All parsing is defensive: unknown or weak key types are rejected.
package sshkeys

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxLineLen bounds one authorized_keys line (options + key + comment).
const MaxLineLen = 16 << 10

// MinRSABits is the minimum accepted RSA modulus size.
const MinRSABits = 3072

// Key is a parsed authorized_keys entry.
type Key struct {
	Type        string   `json:"type"`
	Bits        int      `json:"bits"`
	Fingerprint string   `json:"fingerprint"` // SHA256:… (OpenSSH format)
	Comment     string   `json:"comment"`
	Options     []string `json:"options,omitempty"`
	Blob        string   `json:"-"` // base64 key blob
	Line        int      `json:"line"`
	Raw         string   `json:"-"` // normalised line as written to disk
}

var allowedTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"sk-ssh-ed25519@openssh.com":         true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
	"ssh-rsa":                            true,
}

// known options (authorized_keys(5) "AUTHORIZED_KEYS FILE FORMAT"); anything
// else is rejected so a pasted line cannot smuggle unexpected directives.
var flagOptions = map[string]bool{
	"agent-forwarding": true, "cert-authority": true, "no-agent-forwarding": true, "no-port-forwarding": true,
	"no-pty": true, "no-user-rc": true, "no-X11-forwarding": true, "port-forwarding": true, "pty": true,
	"restrict": true, "user-rc": true, "X11-forwarding": true, "no-touch-required": true, "touch-required": true,
	"verify-required": true,
}
var valueOptions = map[string]bool{
	"command": true, "environment": true, "expiry-time": true, "from": true, "permitlisten": true,
	"permitopen": true, "principals": true, "tunnel": true,
}

// Errors.
var (
	ErrEmpty        = errors.New("empty line")
	ErrTooLong      = errors.New("line too long")
	ErrControl      = errors.New("control characters are not allowed")
	ErrType         = errors.New("unsupported or insecure key type")
	ErrBlob         = errors.New("invalid key data")
	ErrWeakRSA      = fmt.Errorf("RSA keys must have at least %d bits", MinRSABits)
	ErrOption       = errors.New("unknown or malformed option")
	ErrPrivateKey   = errors.New("this is a private key – paste the public key (.pub) instead")
	ErrMultiLine    = errors.New("exactly one key per entry")
	ErrTypeMismatch = errors.New("key type does not match key data")
)

// splitOptions splits the leading options field honouring double quotes.
func splitOptions(s string) (opts []string, rest string, err error) {
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQ && i+1 < len(s) && s[i+1] == '"':
			cur.WriteString(`\"`)
			i++
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case c == ',' && !inQ:
			opts = append(opts, cur.String())
			cur.Reset()
		case (c == ' ' || c == '\t') && !inQ:
			opts = append(opts, cur.String())
			return opts, strings.TrimLeft(s[i:], " \t"), nil
		default:
			cur.WriteByte(c)
		}
	}
	return nil, "", ErrOption
}

func validOption(o string) bool {
	if flagOptions[o] {
		return true
	}
	name, val, ok := strings.Cut(o, "=")
	if !ok || !valueOptions[name] || len(val) < 2 || val[0] != '"' || val[len(val)-1] != '"' {
		return false
	}
	return true
}

var fromRE = regexp.MustCompile(`^[0-9A-Za-z.:/*?!,\-]+$`)

// Parse parses one authorized_keys line (options are optional).
func Parse(line string) (Key, error) {
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	switch {
	case line == "":
		return Key{}, ErrEmpty
	case len(line) > MaxLineLen:
		return Key{}, ErrTooLong
	case strings.Contains(line, "PRIVATE KEY"):
		return Key{}, ErrPrivateKey
	case strings.ContainsAny(line, "\n\x00"):
		return Key{}, ErrMultiLine
	case !utf8.ValidString(line):
		return Key{}, ErrControl
	}
	for _, r := range line {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return Key{}, ErrControl
		}
	}
	var k Key
	rest := line
	first, _, _ := strings.Cut(rest, " ")
	if !allowedTypes[first] && !strings.HasPrefix(first, "ssh-") && !strings.HasPrefix(first, "ecdsa-") && !strings.HasPrefix(first, "sk-") {
		opts, r, err := splitOptions(rest)
		if err != nil {
			return Key{}, ErrOption
		}
		for _, o := range opts {
			if !validOption(o) {
				return Key{}, ErrOption
			}
			if v, ok := strings.CutPrefix(o, "from="); ok && !fromRE.MatchString(strings.Trim(v, `"`)) {
				return Key{}, ErrOption
			}
		}
		k.Options, rest = opts, r
	}
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return Key{}, ErrBlob
	}
	k.Type, k.Blob = fields[0], fields[1]
	if len(fields) > 2 {
		k.Comment = strings.Join(fields[2:], " ")
	}
	if !allowedTypes[k.Type] {
		return Key{}, ErrType
	}
	raw, err := base64.StdEncoding.DecodeString(k.Blob)
	if err != nil {
		return Key{}, ErrBlob
	}
	bits, err := inspect(k.Type, raw)
	if err != nil {
		return Key{}, err
	}
	k.Bits = bits
	sum := sha256.Sum256(raw)
	k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	k.Raw = k.render()
	return k, nil
}

func (k Key) render() string {
	var b strings.Builder
	if len(k.Options) > 0 {
		b.WriteString(strings.Join(k.Options, ","))
		b.WriteByte(' ')
	}
	b.WriteString(k.Type)
	b.WriteByte(' ')
	b.WriteString(k.Blob)
	if k.Comment != "" {
		b.WriteByte(' ')
		b.WriteString(k.Comment)
	}
	return b.String()
}

// WithOptions returns a copy of k with new options (validated).
func (k Key) WithOptions(opts []string) (Key, error) {
	for _, o := range opts {
		if !validOption(o) {
			return Key{}, ErrOption
		}
		if v, ok := strings.CutPrefix(o, "from="); ok && !fromRE.MatchString(strings.Trim(v, `"`)) {
			return Key{}, ErrOption
		}
		if strings.ContainsAny(o, "\n\r\x00") {
			return Key{}, ErrControl
		}
	}
	k.Options = opts
	k.Raw = k.render()
	return k, nil
}

// readString reads an SSH wire-format string.
func readString(b []byte) (s, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, ErrBlob
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, ErrBlob
	}
	return b[4 : 4+n], b[4+n:], nil
}

// inspect checks that the blob matches the declared type and returns the key size in bits.
func inspect(typ string, raw []byte) (int, error) {
	t, rest, err := readString(raw)
	if err != nil {
		return 0, err
	}
	if string(t) != typ {
		return 0, ErrTypeMismatch
	}
	switch typ {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		pk, rest, err := readString(rest)
		if err != nil || len(pk) != 32 {
			return 0, ErrBlob
		}
		if typ == "sk-ssh-ed25519@openssh.com" {
			if _, _, err := readString(rest); err != nil { // application
				return 0, ErrBlob
			}
		}
		return 256, nil
	case "ssh-rsa":
		e, rest, err := readString(rest)
		if err != nil || len(e) == 0 || len(e) > 8 {
			return 0, ErrBlob
		}
		n, _, err := readString(rest)
		if err != nil {
			return 0, ErrBlob
		}
		bits := new(big.Int).SetBytes(n).BitLen()
		if bits < MinRSABits {
			return bits, ErrWeakRSA
		}
		return bits, nil
	default: // ecdsa / sk-ecdsa
		curve, rest, err := readString(rest)
		if err != nil {
			return 0, ErrBlob
		}
		want := map[string]string{"nistp256": "ecdsa-sha2-nistp256", "nistp384": "ecdsa-sha2-nistp384", "nistp521": "ecdsa-sha2-nistp521"}
		bits := map[string]int{"nistp256": 256, "nistp384": 384, "nistp521": 521}[string(curve)]
		if bits == 0 || (typ != "sk-ecdsa-sha2-nistp256@openssh.com" && want[string(curve)] != typ) {
			return 0, ErrTypeMismatch
		}
		if _, _, err := readString(rest); err != nil {
			return 0, ErrBlob
		}
		return bits, nil
	}
}

// File is a parsed authorized_keys file. Lines that are not valid entries
// (comments, unsupported keys) are preserved verbatim on rewrite.
type File struct {
	Keys  []Key    `json:"keys"`
	Other []string `json:"-"` // non-key lines kept in place
	lines []string
	idx   map[int]int // line number → key index
}

// ParseFile parses file content. Invalid key lines are reported as
// Invalid (line numbers) but kept unchanged when the file is rewritten.
func ParseFile(content string) (*File, []int) {
	f := &File{idx: map[int]int{}}
	var invalid []int
	for i, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		f.lines = append(f.lines, l)
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, err := Parse(l)
		if err != nil {
			invalid = append(invalid, i+1)
			continue
		}
		k.Line = i + 1
		f.idx[i] = len(f.Keys)
		f.Keys = append(f.Keys, k)
	}
	if len(f.lines) == 1 && f.lines[0] == "" {
		f.lines = nil
	}
	return f, invalid
}

// Has reports whether a key with the same blob exists.
func (f *File) Has(k Key) bool {
	for _, x := range f.Keys {
		if x.Blob == k.Blob {
			return true
		}
	}
	return false
}

// Add appends a key.
func (f *File) Add(k Key) {
	f.lines = append(f.lines, k.Raw)
	k.Line = len(f.lines)
	f.idx[len(f.lines)-1] = len(f.Keys)
	f.Keys = append(f.Keys, k)
}

// Remove deletes the key with the given fingerprint; returns false if absent.
func (f *File) Remove(fingerprint string) bool {
	for i := range f.lines {
		ki, ok := f.idx[i]
		if !ok || f.Keys[ki].Fingerprint != fingerprint {
			continue
		}
		f.lines = append(f.lines[:i], f.lines[i+1:]...)
		nf, _ := ParseFile(strings.Join(f.lines, "\n"))
		*f = *nf
		return true
	}
	return false
}

// Replace swaps the line of the key with fingerprint for k (e.g. new options).
func (f *File) Replace(fingerprint string, k Key) bool {
	for i := range f.lines {
		ki, ok := f.idx[i]
		if ok && f.Keys[ki].Fingerprint == fingerprint {
			f.lines[i] = k.Raw
			nf, _ := ParseFile(strings.Join(f.lines, "\n"))
			*f = *nf
			return true
		}
	}
	return false
}

// Find returns the key with fingerprint.
func (f *File) Find(fingerprint string) (Key, bool) {
	for _, k := range f.Keys {
		if k.Fingerprint == fingerprint {
			return k, true
		}
	}
	return Key{}, false
}

// String renders the file.
func (f *File) String() string {
	if len(f.lines) == 0 {
		return ""
	}
	return strings.Join(f.lines, "\n") + "\n"
}
