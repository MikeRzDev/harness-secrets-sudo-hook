// Package secrets runs a command with stored secrets in its environment or in
// temporary files, after checking the user's rules and asking the user. See
// docs/secrets.md.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/envfile"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/runner"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/sysbin"
)

// MaxValue is the largest secret psudo stores.
const MaxValue = 64 << 10

// MaxRemember bounds remember_seconds.
const MaxRemember = 86400

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	varRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// ValidName reports whether name is a valid secret name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Several SSH hosts may each have a secret of the same name, with values of
// their own: an "ollama-api-key" on one host is not the one on another. So a
// secret used with -H is, unless its rule shares it with that host, the
// host's own secret, kept and ruled under the key "<name>@<host>". The host
// is the -H argument as given. A name never contains "@", so the first one
// separates the two, and a host may contain more (root@dev).

// HostKey is the key of the secret called name that belongs to host.
func HostKey(name, host string) string { return name + "@" + host }

// SplitKey returns the secret name and the host of a key; host is "" for a
// secret that belongs to no single host.
func SplitKey(key string) (name, host string) {
	name, host, _ = strings.Cut(key, "@")
	return name, host
}

// ValidKey reports whether key is a valid secret name, or a valid name with
// the host it belongs to.
func ValidKey(key string) bool {
	name, host, scoped := strings.Cut(key, "@")
	return ValidName(name) && (!scoped || validHost(host))
}

func validHost(h string) bool { return len(h) <= maxHostLen && runner.ValidHost(h) && plain(h) }

// ownVar is the variable a secret goes into when its rule has no vars: the
// name in upper case with "_" for "-", whatever host the secret belongs to.
func ownVar(key string) (string, bool) {
	name, _ := SplitKey(key)
	return envfile.Key(name)
}

// Scope returns the key of the secret called name for a request on host.
//
//   - On this computer it is the name itself.
//   - A rule for the host's own secret ("<name>@<host>") picks that one.
//   - A rule for the name that lists the host in ssh_hosts shares that
//     secret with the host, as before.
//   - A rule for the name that does not list the host belongs to other
//     hosts: this host gets a secret of its own, which psudo asks the user
//     for, instead of a refusal.
//   - With no rule at all, a value stored under the plain name (with
//     --secret-set, say) is offered for this host, as before; otherwise the
//     new secret is the host's own, so that another host can later have one
//     under the same name.
//
// stored reports whether a value is kept under a key in the session or the
// OS credential store; it is called only in the last case.
func Scope(p Policy, host, name string, stored func(key string) (bool, error)) (string, error) {
	if host == "" {
		return name, nil
	}
	own := HostKey(name, host)
	if _, ok := p[own]; ok {
		return own, nil
	}
	if rule, ok := p[name]; ok {
		if slices.Contains(rule.SSHHosts, host) {
			return name, nil
		}
		return own, nil
	}
	ok, err := stored(name)
	if err != nil {
		return "", err
	}
	if ok {
		return name, nil
	}
	return own, nil
}

// reservedVars and reservedPrefixes are variables that make a program load
// code, run another program or read its settings from somewhere else: the
// loader, shells, interpreters, git, npm, pagers and editors. A value put in
// one of them is an instruction, not a credential, so no secret may go there.
//
// The list cannot be complete, since every tool has variables of its own. It
// is not what keeps a secret safe. Two other rules are: a rule names the
// variables its secret may be put in (Rule.Vars), and a value from an env
// file, which the agent can write, never shares a command with a stored
// secret (Runner.Run).
var reservedVars = map[string]bool{"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"TMPDIR": true, "IFS": true, "ENV": true, "BASH_ENV": true, "SSH_AUTH_SOCK": true,
	"CDPATH": true, "GLOBIGNORE": true, "SHELLOPTS": true, "BASHOPTS": true, "PROMPT_COMMAND": true, "PS4": true,
	"HISTFILE": true, "ZDOTDIR": true, "FPATH": true,
	"NODE_OPTIONS": true, "NODE_PATH": true, "PERLLIB": true, "RUBYOPT": true, "RUBYLIB": true, "RUBYSHELL": true,
	"GEM_HOME": true, "GEM_PATH": true, "BUNDLE_GEMFILE": true,
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true,
	"GOFLAGS": true, "MAKEFLAGS": true, "RUSTC_WRAPPER": true,
	"GCONV_PATH": true, "LOCPATH": true, "NLSPATH": true, "HOSTALIASES": true, "TERMINFO": true, "TERMCAP": true,
	"BROWSER": true, "EDITOR": true, "VISUAL": true, "PAGER": true, "MANPAGER": true, "LESSOPEN": true, "LESSCLOSE": true,
	"SSH_ASKPASS": true, "SUDO_ASKPASS": true, "CFFIXED_USER_HOME": true}

var reservedPrefixes = []string{"LD_", "DYLD_", "PSUDO_", "BASH_", "PYTHON", "PERL5", "GIT_", "XDG_",
	"NPM_CONFIG_", "npm_config_"}

// ValidVar reports whether v may receive a secret.
func ValidVar(v string) bool {
	if !varRe.MatchString(v) || reservedVars[v] {
		return false
	}
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	return true
}

// forbidden programs can never receive a secret: they print it, or run a
// program or code chosen in their arguments. coreutils and toybox are
// multi-call binaries like busybox: the name they are run under picks the
// program, so allowing one of their programs would allow env and cat too.
var forbidden = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "fish": true, "csh": true,
	"tcsh": true, "ash": true, "busybox": true, "env": true, "printenv": true, "echo": true, "printf": true,
	"cat": true, "tee": true, "xargs": true, "nohup": true, "time": true, "exec": true, "command": true,
	"builtin": true, "eval": true, "nice": true, "ionice": true, "timeout": true, "stdbuf": true, "watch": true,
	"setsid": true, "script": true, "sudo": true, "doas": true, "su": true, "sshpass": true, "ssh": true,
	"scp": true, "sftp": true, "run0": true, "pkexec": true, "runuser": true, "chroot": true, "nsenter": true,
	"unshare": true, "systemd-run": true, "strace": true, "ltrace": true, "gdb": true, "lldb": true,
	"dtruss": true, "osascript": true, "expect": true, "psudo": true, "flock": true, "parallel": true,
	"caffeinate": true, "unbuffer": true, "find": true, "coreutils": true, "toybox": true,
}

// Rule is what the user allows for one secret (docs/secrets.md §5.3).
type Rule struct {
	Commands []string
	// Vars are the variables the secret may be put in. The caller picks the
	// variable of each request, and the name decides what a program does with
	// the value: a token given to git as GIT_AUTHOR_NAME ends up in a commit
	// anyone can read. So the variable is part of the rule. Without vars, the
	// only one allowed is the secret's own name in upper case with "_" for
	// "-" (github-token is GITHUB_TOKEN).
	Vars            []string
	Local           bool
	SSHHosts        []string
	Confirm         bool
	RememberSeconds int
}

// allowsVar reports whether the rule for the secret called name lets it be
// put in the variable v.
func (r Rule) allowsVar(name, v string) bool {
	if len(r.Vars) > 0 {
		return slices.Contains(r.Vars, v)
	}
	own, ok := ownVar(name)
	return ok && v == own
}

// Policy maps secret names to rules.
type Policy map[string]Rule

// ErrConfig reports invalid rules. Every secret request fails closed on it.
var ErrConfig = errors.New("invalid secrets rules")

// ParsePolicy reads the "secrets" object of the config file. A config
// without one has no rules.
func ParsePolicy(data []byte) (Policy, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(data), &top); err != nil {
		return nil, fmt.Errorf("%w: config must be a JSON object", ErrConfig)
	}
	raw, ok := top["secrets"]
	if !ok {
		return Policy{}, nil
	}
	var entries map[string]json.RawMessage
	if err := strictObject(raw, &entries); err != nil {
		return nil, fmt.Errorf("%w: secrets must be an object", ErrConfig)
	}
	p := Policy{}
	for name, body := range entries {
		if !ValidKey(name) {
			return nil, fmt.Errorf("%w: %q is not a valid secret name (or <name>@<ssh host>)", ErrConfig, name)
		}
		rule, err := parseRule(name, body)
		if err != nil {
			return nil, err
		}
		p[name] = rule
	}
	return p, nil
}

func strictObject(raw json.RawMessage, v any) error {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' {
		return errors.New("not an object")
	}
	return json.Unmarshal(t, v)
}

func parseRule(name string, body json.RawMessage) (Rule, error) {
	bad := func(format string, args ...any) (Rule, error) {
		return Rule{}, fmt.Errorf("%w: secrets.%s: "+format, append([]any{ErrConfig, name}, args...)...)
	}
	var fields map[string]json.RawMessage
	if err := strictObject(body, &fields); err != nil {
		return bad("must be an object")
	}
	// confirm is false unless the rule says otherwise: a program the rule
	// lists gets the secret without a dialog before each use.
	r := Rule{Local: true}
	_, host := SplitKey(name)
	for key, value := range fields {
		var err error
		if host != "" && (key == "local" || key == "ssh_hosts") {
			// A host's own secret is used on that host only: the name says so.
			return bad("%s is not used in a rule for one host's secret; the host comes from the name", key)
		}
		switch key {
		case "commands":
			err = json.Unmarshal(value, &r.Commands)
		case "vars":
			err = json.Unmarshal(value, &r.Vars)
		case "ssh_hosts":
			err = json.Unmarshal(value, &r.SSHHosts)
		case "local":
			err = strictBool(value, &r.Local)
		case "confirm":
			err = strictBool(value, &r.Confirm)
		case "remember_seconds":
			err = json.Unmarshal(value, &r.RememberSeconds)
			if err == nil && (r.RememberSeconds < 0 || r.RememberSeconds > MaxRemember) {
				return bad("remember_seconds must be from 0 to %d", MaxRemember)
			}
		default:
			return bad("unknown field %q", key)
		}
		if err != nil {
			return bad("%s has the wrong type", key)
		}
	}
	if host != "" {
		r.Local, r.SSHHosts = false, []string{host}
	}
	if err := r.Validate(); err != nil {
		return bad("%v", err)
	}
	return r, nil
}

// Limits on what a rule may contain. The rules are shown to the user for
// approval, so every string in them must fit on a line and be readable.
const (
	maxCommandLen = 1024
	maxHostLen    = 255
	maxEntries    = 64
)

// plain reports whether s can be shown on one line as it is: no control
// characters, no invisible or direction-changing characters, and no space
// other than the ASCII one.
func plain(s string) bool {
	for _, r := range s {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return false
		}
	}
	return s == strings.TrimSpace(s)
}

// Validate reports what is wrong with a rule's commands and hosts. It applies
// to rules read from the config file and to rules psudo suggests.
func (r Rule) Validate() error {
	if len(r.Commands) == 0 {
		return errors.New("commands must list at least one program")
	}
	if len(r.Commands) > maxEntries || len(r.SSHHosts) > maxEntries || len(r.Vars) > maxEntries {
		return fmt.Errorf("commands, vars and ssh_hosts may each list at most %d entries", maxEntries)
	}
	for _, v := range r.Vars {
		if !ValidVar(v) {
			return fmt.Errorf("%q in vars is not a variable a secret may be put in", v)
		}
	}
	for _, c := range r.Commands {
		if c == "" || (strings.Contains(c, "/") && !filepath.IsAbs(c) && !strings.HasPrefix(c, "~/")) {
			return fmt.Errorf("command %q must be a program name or an absolute path", c)
		}
		if len(c) > maxCommandLen || !plain(c) {
			return fmt.Errorf("command %q must be plain text on one line (at most %d bytes)", c, maxCommandLen)
		}
		if forbiddenName(filepath.Base(c)) {
			return fmt.Errorf("%q cannot receive secrets: it can print them or run other programs", c)
		}
	}
	for _, h := range r.SSHHosts {
		if !validHost(h) {
			return fmt.Errorf("ssh host %q is not valid", h)
		}
	}
	return nil
}

func strictBool(raw json.RawMessage, b *bool) error {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		return errors.New("not a boolean")
	}
	return nil
}

// LoadPolicy reads the rules from path; a missing file has no rules.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Policy{}, nil
	}
	if err != nil {
		return nil, err
	}
	return ParsePolicy(data)
}

// Use is one secret delivered to the command.
type Use struct {
	Var, Name string
	File      bool
}

// ParseUse parses VAR=name.
func ParseUse(s string, file bool) (Use, error) {
	v, name, ok := strings.Cut(s, "=")
	if !ok || !ValidVar(v) {
		return Use{}, fmt.Errorf("%q: expected VAR=name with a usable variable name", s)
	}
	if !ValidName(name) {
		return Use{}, fmt.Errorf("%q: secret names use a-z, 0-9, _ and -", s)
	}
	return Use{Var: v, Name: name, File: file}, nil
}

// Request is one psudo --secret invocation.
type Request struct {
	Host string // "" is this computer
	Dir  string // working directory, shown in the dialog
	Uses []Use
	Argv []string
}

// Decision is the result of checking a request against the policy.
type Decision struct {
	Path     string // the program to run locally; "" on a remote host
	Confirm  bool
	Remember int // seconds; 0 offers only "Allow once"
	// Entry is, for each secret, the entry of its rule's commands that
	// allowed the program. The program a user allowed is remembered under
	// that entry (see pins.go), not under the path it resolves to today.
	Entry map[string]string
}

// forbiddenName reports whether a program name is one that can never receive
// a secret. Case does not count: on a file system that ignores case, as macOS
// has by default, /bin/SH is /bin/sh.
func forbiddenName(name string) bool { return forbidden[strings.ToLower(name)] }

// forbiddenFile reports whether file is one of the forbidden programs under
// another name: the same file as one of them (a hard link, or a path that
// differs only in case), found through find.
func forbiddenFile(file string, find func(string) string) bool {
	info, err := os.Stat(file)
	if err != nil {
		return false
	}
	for name := range forbidden {
		if p := find(name); p != "" {
			if other, err := os.Stat(p); err == nil && os.SameFile(info, other) {
				return true
			}
		}
	}
	return false
}

// runsCode matches programs whose job is to run code they are given, in an
// argument or a file: interpreters. A rule cannot say what such a program
// will do with a secret, so a rule psudo suggests for one asks before each
// use ("confirm": true), with the whole command in the dialog.
var runsCode = regexp.MustCompile(`^(python[0-9.]*|pypy[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|deno|bun|tsx|ts-node|` +
	`php[0-9.]*|[gmn]?awk|lua[0-9.]*|luajit|tclsh[0-9.]*|wish|rscript|pwsh|powershell|swift|groovy|jshell|jrunscript|irb|` +
	`java|scala|kotlin|elixir|erl|ghci|runghc|runhaskell|racket|guile|julia|octave|sbcl|clojure|bb)$`)

// RunsCode reports whether the program is an interpreter, going by its name.
func RunsCode(program string) bool {
	return runsCode.MatchString(strings.ToLower(filepath.Base(program)))
}

// commonInterpreters are looked up through find, to recognise one of them
// under another name.
var commonInterpreters = []string{"python3", "python", "perl", "ruby", "node", "nodejs", "deno", "bun", "php",
	"awk", "gawk", "mawk", "nawk", "lua", "tclsh", "Rscript", "swift", "java", "pwsh"}

// interpreterFile reports whether file, the resolved program, is an
// interpreter: by its own name, or because it is the same file as an
// interpreter found through find (a hard link under another name). A copy of
// an interpreter under another name is not recognised.
func interpreterFile(file string, find func(string) string) bool {
	if RunsCode(file) {
		return true
	}
	info, err := os.Stat(file)
	if err != nil {
		return false
	}
	for _, name := range commonInterpreters {
		if p := find(name); p != "" {
			if other, err := os.Stat(p); err == nil && os.SameFile(info, other) {
				return true
			}
		}
	}
	return false
}

// Refusal explains why a request is not allowed. It names what the user
// would have to change.
type Refusal struct{ Msg string }

func (r *Refusal) Error() string { return r.Msg }

func refuse(format string, args ...any) *Refusal { return &Refusal{fmt.Sprintf(format, args...)} }

// homeDir is where "~/" in a rule points: the account's home directory, not
// $HOME. The caller of psudo sets $HOME, and could otherwise make a rule for
// ~/bin/tool match a file in a folder of its own.
var homeDir = cache.Home

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home := homeDir(); home != "" {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func same(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}

// Check decides whether req may run. find resolves a bare program name in
// the trusted directories (sysbin.Find in production).
func Check(p Policy, req Request, find func(string) string) (Decision, error) {
	if len(req.Argv) == 0 || len(req.Uses) == 0 {
		return Decision{}, refuse("no command or no secret given")
	}
	seen := map[string]bool{}
	for _, u := range req.Uses {
		if seen[u.Var] {
			return Decision{}, refuse("%s is given more than once", u.Var)
		}
		seen[u.Var] = true
	}
	argv0 := req.Argv[0]
	// On an SSH host the name is all psudo has to go on; locally the resolved
	// file is checked as well, below.
	if argv0 == "" || forbiddenName(filepath.Base(argv0)) {
		return Decision{}, refuse("%q can never receive secrets", argv0)
	}
	d := Decision{Remember: MaxRemember, Entry: map[string]string{}}
	if req.Host == "" {
		switch {
		case strings.Contains(argv0, "/") && !filepath.IsAbs(argv0):
			return Decision{}, refuse("%q is a relative path; give a program name or an absolute path", argv0)
		case strings.Contains(argv0, "/"):
			d.Path = filepath.Clean(argv0)
		default:
			d.Path = find(argv0)
			if d.Path == "" {
				return Decision{}, refuse("%q was not found in the system directories psudo trusts (%s); "+
					"the user can allow it by absolute path in the rule's commands", argv0, strings.Join(sysbin.Dirs, ", "))
			}
		}
		// Resolve once and run exactly the resolved file: a symlink checked
		// here could otherwise be repointed while the dialog is open.
		real, err := filepath.EvalSymlinks(d.Path)
		if err != nil {
			return Decision{}, refuse("%q could not be resolved: %v", argv0, err)
		}
		d.Path = real
		if forbiddenName(filepath.Base(real)) || forbiddenFile(real, find) {
			return Decision{}, refuse("%q can never receive secrets", argv0)
		}
	}
	confirm := false
	for _, u := range req.Uses {
		rule, ok := p[u.Name]
		if !ok {
			return Decision{}, refuse("there is no rule for secret %q; the user must add one under \"secrets\" in config.json", u.Name)
		}
		if req.Host == "" && !rule.Local {
			return Decision{}, refuse("secret %q may not be used on this computer (its rule sets \"local\": false)", u.Name)
		}
		if req.Host != "" && !slices.Contains(rule.SSHHosts, req.Host) {
			return Decision{}, refuse("secret %q may not be used on %s (not in its rule's ssh_hosts)", u.Name, req.Host)
		}
		entry, ok := commandAllowed(rule.Commands, req.Host, argv0, d.Path, find)
		if !ok {
			return Decision{}, refuse("secret %q may not be used with %q (not in its rule's commands)", u.Name, argv0)
		}
		d.Entry[u.Name] = entry
		if !rule.allowsVar(u.Name, u.Var) {
			if len(rule.Vars) > 0 {
				return Decision{}, refuse("secret %q may not be put in %s (its rule's vars allow: %s)", u.Name, u.Var,
					strings.Join(rule.Vars, ", "))
			}
			own, _ := ownVar(u.Name)
			return Decision{}, refuse("secret %q may not be put in %s (its rule has no \"vars\", so only %s is allowed)",
				u.Name, u.Var, own)
		}
		confirm = confirm || rule.Confirm
		if rule.Confirm && rule.RememberSeconds < d.Remember {
			d.Remember = rule.RememberSeconds
		}
	}
	d.Confirm = confirm
	if !confirm {
		d.Remember = 0
	}
	return d, nil
}

// commandAllowed returns the entry of a rule's commands that allows the
// program, if there is one.
func commandAllowed(entries []string, host, argv0, path string, find func(string) string) (string, bool) {
	for _, e := range entries {
		bare := !strings.Contains(e, "/")
		if host != "" {
			// Remote: the name as given must match the entry exactly.
			if bare && argv0 == e || !bare && filepath.IsAbs(e) && filepath.Clean(argv0) == filepath.Clean(e) {
				return e, true
			}
			continue
		}
		if bare {
			if f := find(e); f != "" && same(f, path) {
				return e, true
			}
		} else if same(expand(e), path) {
			return e, true
		}
	}
	return "", false
}

// Names returns the secret names in uses, sorted and unique.
func Names(uses []Use) []string {
	set := map[string]bool{}
	for _, u := range uses {
		set[u.Name] = true
	}
	var out []string
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
