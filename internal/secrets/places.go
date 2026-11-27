package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/envfile"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/proc"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/vault"
)

// Place is somewhere the value of a secret is kept (docs/secrets.md §6). A
// value the user enters is kept for the session unless the user chooses one
// of the lasting places: the project's git-ignored env file or the OS
// credential store.
type Place interface {
	// Name is how dialogs call the place: "this session", ".env.local",
	// "the Keychain".
	Name() string
	// Note is one sentence for the dialog that asks where to keep a value.
	Note(secret string) string
	Has(name string) (bool, error)
	// Get returns the value, or nil when the place has none.
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
}

// lookup returns the first of places that has a value for name. A nil place
// is skipped.
func lookup(places []Place, name string) (Place, error) {
	for _, p := range places {
		if p == nil {
			continue
		}
		ok, err := p.Has(name)
		if err != nil {
			return nil, err
		}
		if ok {
			return p, nil
		}
	}
	return nil, nil
}

// StoreName is the name under which the value of the secret with this key is
// kept in the OS credential store. A host may contain characters an entry
// name cannot (dots, quotes), so the host part is in hex: ollama-api-key@dev
// is kept as ollama-api-key@646576.
func StoreName(key string) string {
	name, host := SplitKey(key)
	if host == "" {
		return name
	}
	return name + "@" + hex.EncodeToString([]byte(host))
}

// KeyOfStore is the reverse of StoreName; ok is false for a name StoreName
// cannot have made.
func KeyOfStore(stored string) (string, bool) {
	name, h, scoped := strings.Cut(stored, "@")
	if !scoped {
		return name, ValidName(name)
	}
	host, err := hex.DecodeString(h)
	if err != nil || hex.EncodeToString(host) != h || !ValidKey(HostKey(name, string(host))) {
		return "", false
	}
	return HostKey(name, string(host)), true
}

// --- the OS credential store

type securePlace struct {
	v    vault.Vault
	name string
}

// Secure is the OS credential store as a place. name is its name in dialogs,
// such as "the Keychain".
func Secure(v vault.Vault, name string) Place {
	if name == "" {
		name = "the OS credential store"
	}
	return &securePlace{v, name}
}

func (s *securePlace) Name() string { return s.name }

func (s *securePlace) Note(string) string {
	return "kept for every project and every session, until you delete it. The agent is not given the value."
}

func (s *securePlace) Has(name string) (bool, error)       { return s.v.Has(StoreName(name)) }
func (s *securePlace) Get(name string) ([]byte, error)     { return s.v.Get(StoreName(name)) }
func (s *securePlace) Put(name string, value []byte) error { return s.v.Put(StoreName(name), value) }

// --- the session

// Session identifies the harness session psudo was started from: the
// harness's own session id, and the harness process, which is an ancestor of
// this psudo.
type Session struct {
	Harness string
	ID      string
	PID     int
}

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

// sessionEnv names the variable in which each harness gives its tool commands
// the session id.
var sessionEnv = map[string]string{"claude-code": "CLAUDE_CODE_SESSION_ID", "codex": "CODEX_THREAD_ID"}

// harnessProcess reports whether a process name is the harness itself.
func harnessProcess(harness, name string) bool {
	if harness == "codex" {
		return len(name) >= 5 && name[:5] == "codex"
	}
	return name == "claude"
}

// DetectSession works out the session from the environment the harness gives
// its tool commands and from the ancestors of this process (nearest first).
//
// The session id comes from the environment, which the caller controls, so it
// is not what protects a session's secrets. The harness process is: it is the
// nearest ancestor that is the harness program, and a secret kept for a
// session is filed under that process id. A caller that claims another
// session's id is still not a descendant of that session's harness, so it
// finds nothing. Claude Code also names its process in CLAUDE_PID; that is
// used only when no ancestor has the harness's name (an install that runs
// under node), and only when it really is an ancestor.
func DetectSession(harness string, getenv func(string) string, ancestors []proc.Proc) (Session, bool) {
	id := getenv(sessionEnv[harness])
	if !sessionIDRe.MatchString(id) {
		return Session{}, false
	}
	for _, p := range ancestors {
		if harnessProcess(harness, p.Name) {
			return Session{harness, id, p.PID}, true
		}
	}
	if harness == "claude-code" {
		if pid, err := strconv.Atoi(getenv("CLAUDE_PID")); err == nil && pid > 1 {
			for _, p := range ancestors {
				if p.PID == pid {
					return Session{harness, id, pid}, true
				}
			}
		}
	}
	return Session{}, false
}

// sessionKey is the part of an entry name that stands for a session id.
func sessionKey(harness, id string) string {
	sum := sha256.Sum256([]byte(harness + "\x00" + id))
	return hex.EncodeToString(sum[:8])
}

// A session entry is named <harness pid>-<session key>-<secret name>. The
// process id is in the name so that entries of a dead harness can be found
// and removed without decrypting anything.
var sessionEntryRe = regexp.MustCompile(`^([0-9]+)-([0-9a-f]{16})-(.+)$`)

type sessionPlace struct {
	v      vault.Vault
	prefix string
	what   string
}

// SessionPlace keeps values for one session in v, the "session" namespace of
// the OS credential store. what names the harness in dialogs ("Claude Code").
func SessionPlace(v vault.Vault, s Session, what string) Place {
	return &sessionPlace{v, fmt.Sprintf("%d-%s-", s.PID, sessionKey(s.Harness, s.ID)), what}
}

func (s *sessionPlace) Name() string { return "this session" }

func (s *sessionPlace) Note(string) string {
	return "psudo forgets it when this " + s.what + " session ends. The agent is not given the value."
}

func (s *sessionPlace) Has(name string) (bool, error)   { return s.v.Has(s.prefix + StoreName(name)) }
func (s *sessionPlace) Get(name string) ([]byte, error) { return s.v.Get(s.prefix + StoreName(name)) }
func (s *sessionPlace) Put(name string, value []byte) error {
	return s.v.Put(s.prefix+StoreName(name), value)
}

// SessionNames returns the secrets kept for session s.
func SessionNames(v vault.Vault, s Session) ([]string, error) {
	entries, err := v.List()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		m := sessionEntryRe.FindStringSubmatch(e)
		if m != nil && m[1] == strconv.Itoa(s.PID) && m[2] == sessionKey(s.Harness, s.ID) {
			if key, ok := KeyOfStore(m[3]); ok {
				names = append(names, key)
			}
		}
	}
	return names, nil
}

// ForgetSession removes one secret of session s.
func ForgetSession(v vault.Vault, s Session, name string) error {
	return v.Delete(fmt.Sprintf("%d-%s-%s", s.PID, sessionKey(s.Harness, s.ID), StoreName(name)))
}

// EndSession removes what was kept for the session with this id, and for
// every session whose harness process is gone (one that crashed, or was
// killed before it could say that it ended). It returns how many entries it
// removed.
func EndSession(v vault.Vault, harness, id string, alive func(pid int) bool) (int, error) {
	entries, err := v.List()
	if err != nil {
		return 0, err
	}
	key := ""
	if sessionIDRe.MatchString(id) {
		key = sessionKey(harness, id)
	}
	removed := 0
	var failed error
	for _, e := range entries {
		m := sessionEntryRe.FindStringSubmatch(e)
		if m == nil {
			continue
		}
		pid, _ := strconv.Atoi(m[1])
		if m[2] != key && alive(pid) {
			continue
		}
		if err := v.Delete(e); err != nil {
			failed = err
			continue
		}
		removed++
	}
	return removed, failed
}

// --- the project's env file

type projectPlace struct {
	project envfile.Project
	git     envfile.Git
}

// ProjectPlace is the git-ignored env file of a project as a place, or nil
// when the project has none.
func ProjectPlace(p envfile.Project, git envfile.Git) Place {
	if p.Save == "" && len(p.Read) == 0 {
		return nil
	}
	return &projectPlace{p, git}
}

func (p *projectPlace) file() string {
	if p.project.Save != "" {
		return p.project.Save
	}
	return p.project.Read[0]
}

func (p *projectPlace) Name() string { return filepath.Base(p.file()) }

func (p *projectPlace) Note(secret string) string {
	key, _ := ownVar(secret)
	return "saved as " + key + " in " + shquote.VisibleLine(p.file()) +
		". Git ignores that file, but it is plain text: the agent, and anything else that reads the project, can read the value."
}

// The env file is the project's: its variable for a secret is the same for
// every host, as it was before secrets belonged to hosts.
func (p *projectPlace) find(name string) ([]byte, bool) {
	key, ok := ownVar(name)
	if !ok {
		return nil, false
	}
	for _, path := range p.project.Read {
		// An empty assignment is a placeholder, not a value. A file that
		// cannot be read has nothing to offer; it is not an error.
		if value, ok, err := envfile.Get(path, key); err == nil && ok && len(value) > 0 {
			return value, true
		}
	}
	return nil, false
}

func (p *projectPlace) Has(name string) (bool, error) {
	value, ok := p.find(name)
	clear(value)
	return ok, nil
}

func (p *projectPlace) Get(name string) ([]byte, error) {
	value, _ := p.find(name)
	return value, nil
}

// CanSave reports whether a value for name can be written to the env file.
//
// A host's own secret is not saved there: the file has one variable for every
// host, so the value would reach the other hosts too.
func (p *projectPlace) CanSave(name string) bool {
	_, host := SplitKey(name)
	_, ok := envfile.Key(name)
	return ok && host == "" && p.project.Save != ""
}

func (p *projectPlace) Put(name string, value []byte) error {
	key, ok := envfile.Key(name)
	if !ok || p.project.Save == "" {
		return errors.New("the project has no env file for this secret")
	}
	// Asked again at the last moment: the file is written only while git
	// still ignores it, so the value cannot end up in a commit.
	if !p.git.Ignored(p.project.Root, p.project.Save) {
		return fmt.Errorf("git no longer ignores %s", p.project.Save)
	}
	if err := envfile.Set(p.project.Save, key, value); err != nil {
		return err
	}
	for _, path := range p.project.Read {
		if path == p.project.Save {
			return nil
		}
	}
	p.project.Read = append([]string{p.project.Save}, p.project.Read...)
	return nil
}
