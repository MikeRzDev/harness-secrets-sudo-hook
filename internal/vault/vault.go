// Package vault stores named values in the OS credential store: the macOS
// Keychain or the Linux Secret Service. Values never pass through argv.
// See docs/secrets.md §6.
package vault

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/sysbin"
)

// Vault is one namespace ("secret", "approvals") of credential-store entries.
type Vault interface {
	// Has reports whether an entry exists. On macOS it does not decrypt it.
	Has(name string) (bool, error)
	// Get returns the value, or nil when there is no entry.
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	// Delete removes the entry; a missing entry is not an error.
	Delete(name string) error
	// List returns the entry names, sorted.
	List() ([]string, error)
}

// ErrStore means the credential store could not be used.
var ErrStore = errors.New("the OS credential store is unavailable")

// New returns the platform vault for kind.
func New(kind string) (Vault, error) {
	switch runtime.GOOS {
	case "darwin":
		return &Keychain{Kind: kind, Account: cache.Account(), Exec: cache.Run}, nil
	case "linux":
		return &SecretService{Kind: kind, Account: cache.Account(), Tool: sysbin.Find("secret-tool"), Exec: cache.Run}, nil
	}
	return nil, cache.ErrUnsupported
}

const securityPath = "/usr/bin/security"

// partSize keeps each `security -i` command line under its 4096-byte limit.
const partSize = 3000

// Keychain stores each value base64-encoded, split into parts: the first
// part is "<count> <data>" under service harness-root-hook.<kind>.<name>,
// the rest under ….<name>.part<i>. Names never contain dots, so part
// services cannot collide with other names.
type Keychain struct {
	Kind, Account string
	Exec          cache.ExecFunc
}

func (k *Keychain) service(name string, part int) string {
	s := "harness-root-hook." + k.Kind + "." + name
	if part > 0 {
		s += ".part" + strconv.Itoa(part)
	}
	return s
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

// read returns one part, or ok=false when it does not exist.
func (k *Keychain) read(service string) (string, bool, error) {
	res, err := k.Exec(securityPath, []string{"find-generic-password", "-s", service, "-a", k.Account, "-w"}, nil)
	if err != nil {
		return "", false, ErrStore
	}
	switch res.Code {
	case 0:
		return strings.TrimSpace(res.Stdout), true, nil
	case 44: // errSecItemNotFound
		return "", false, nil
	}
	return "", false, ErrStore
}

func (k *Keychain) write(service, data string) error {
	args := []string{"add-generic-password", "-U", "-T", securityPath, "-s", service, "-a", k.Account,
		"-j", "psudo " + k.Kind, "-w", data}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = quote(a)
	}
	res, err := k.Exec(securityPath, []string{"-i"}, []byte(strings.Join(quoted, " ")+"\n"))
	if err != nil || res.Code != 0 {
		return ErrStore
	}
	return nil
}

func (k *Keychain) remove(service string) error {
	res, err := k.Exec(securityPath, []string{"delete-generic-password", "-s", service, "-a", k.Account}, nil)
	if err != nil || (res.Code != 0 && res.Code != 44) {
		return ErrStore
	}
	return nil
}

func (k *Keychain) count(name string) (int, string, bool, error) {
	head, ok, err := k.read(k.service(name, 0))
	if err != nil || !ok {
		return 0, "", ok, err
	}
	n, data, found := strings.Cut(head, " ")
	parts, err := strconv.Atoi(n)
	if !found || err != nil || parts < 1 || parts > 64 {
		return 0, "", true, fmt.Errorf("%w: malformed entry %s", ErrStore, name)
	}
	return parts, data, true, nil
}

func (k *Keychain) Has(name string) (bool, error) {
	// Without -w, find-generic-password prints attributes only.
	res, err := k.Exec(securityPath, []string{"find-generic-password", "-s", k.service(name, 0), "-a", k.Account}, nil)
	if err != nil {
		return false, ErrStore
	}
	switch res.Code {
	case 0:
		return true, nil
	case 44:
		return false, nil
	}
	return false, ErrStore
}

func (k *Keychain) Get(name string) ([]byte, error) {
	parts, data, ok, err := k.count(name)
	if err != nil || !ok {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(data)
	for i := 1; i < parts; i++ {
		p, ok, err := k.read(k.service(name, i))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: entry %s is incomplete", ErrStore, name)
		}
		b.WriteString(p)
	}
	value, err := base64.StdEncoding.DecodeString(b.String())
	if err != nil {
		return nil, fmt.Errorf("%w: malformed entry %s", ErrStore, name)
	}
	return value, nil
}

func (k *Keychain) Put(name string, value []byte) error {
	encoded := base64.StdEncoding.EncodeToString(value)
	var pieces []string
	for len(encoded) > partSize {
		pieces = append(pieces, encoded[:partSize])
		encoded = encoded[partSize:]
	}
	pieces = append(pieces, encoded)
	if len(pieces) > 64 {
		return errors.New("value is too large for the Keychain")
	}
	old, _, _, _ := k.count(name)
	// Later parts first, so a reader never sees a header pointing at parts
	// that are not written yet.
	for i := len(pieces) - 1; i >= 1; i-- {
		if err := k.write(k.service(name, i), pieces[i]); err != nil {
			return err
		}
	}
	if err := k.write(k.service(name, 0), strconv.Itoa(len(pieces))+" "+pieces[0]); err != nil {
		return err
	}
	for i := len(pieces); i < old; i++ {
		k.remove(k.service(name, i))
	}
	return nil
}

func (k *Keychain) Delete(name string) error {
	parts, _, ok, _ := k.count(name)
	if !ok {
		parts = 1
	}
	if err := k.remove(k.service(name, 0)); err != nil {
		return err
	}
	for i := 1; i < parts; i++ {
		k.remove(k.service(name, i))
	}
	return nil
}

func (k *Keychain) List() ([]string, error) {
	// Without -d, dump-keychain prints attributes only, never secrets.
	res, err := k.Exec(securityPath, []string{"dump-keychain"}, nil)
	if err != nil || res.Code != 0 {
		return nil, ErrStore
	}
	re := regexp.MustCompile(`"svce"<blob>="harness-root-hook\.` + regexp.QuoteMeta(k.Kind) + `\.([a-z0-9][a-z0-9_@-]*)"`)
	return unique(re.FindAllStringSubmatch(res.Stdout, -1)), nil
}

func unique(matches [][]string) []string {
	seen := map[string]bool{}
	var names []string
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	return names
}

// SecretService stores each value base64-encoded through secret-tool.
type SecretService struct {
	Kind, Account, Tool string
	Exec                cache.ExecFunc
}

func (s *SecretService) attrs(name string) []string {
	a := []string{"application", "harness-root-hook", "kind", s.Kind}
	if name != "" {
		a = append(a, "name", name)
	}
	return append(a, "account", s.Account)
}

func (s *SecretService) run(args []string, stdin []byte) (cache.Result, error) {
	if s.Tool == "" {
		return cache.Result{}, fmt.Errorf("%w: secret-tool is not installed", ErrStore)
	}
	res, err := s.Exec(s.Tool, args, stdin)
	if err != nil {
		return res, ErrStore
	}
	return res, nil
}

// missing is secret-tool's "no matching item": exit 1 with nothing on stderr.
func missing(res cache.Result) bool { return res.Code == 1 && strings.TrimSpace(res.Stderr) == "" }

func (s *SecretService) Has(name string) (bool, error) {
	v, err := s.Get(name)
	clear(v)
	return v != nil, err
}

func (s *SecretService) Get(name string) ([]byte, error) {
	res, err := s.run(append([]string{"lookup"}, s.attrs(name)...), nil)
	if err != nil {
		return nil, err
	}
	if missing(res) {
		return nil, nil
	}
	if res.Code != 0 {
		return nil, ErrStore
	}
	value, err := base64.StdEncoding.DecodeString(strings.TrimSpace(res.Stdout))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed entry %s", ErrStore, name)
	}
	return value, nil
}

func (s *SecretService) Put(name string, value []byte) error {
	args := append([]string{"store", "--label=psudo " + s.Kind + " " + name}, s.attrs(name)...)
	res, err := s.run(args, []byte(base64.StdEncoding.EncodeToString(value)))
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return ErrStore
	}
	return nil
}

func (s *SecretService) Delete(name string) error {
	res, err := s.run(append([]string{"clear"}, s.attrs(name)...), nil)
	if err != nil {
		return err
	}
	if res.Code != 0 && !missing(res) {
		return ErrStore
	}
	return nil
}

func (s *SecretService) List() ([]string, error) {
	res, err := s.run(append([]string{"search", "--all"}, s.attrs("")...), nil)
	if err != nil {
		return nil, err
	}
	if missing(res) {
		return nil, nil
	}
	if res.Code != 0 {
		return nil, ErrStore
	}
	// search prints attributes on stdout or stderr depending on the version.
	re := regexp.MustCompile(`(?m)^attribute\.name = ([a-z0-9][a-z0-9_@-]*)$`)
	return unique(re.FindAllStringSubmatch(res.Stdout+"\n"+res.Stderr, -1)), nil
}
