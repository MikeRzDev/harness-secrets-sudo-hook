package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/envfile"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/proc"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/prompt"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/runner"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/secrets"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/sysbin"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/vault"
)

// secretOption reports whether a is --secret or --secret-file, with or
// without an inline =VAR=name.
func secretOption(a string) bool {
	opt, _, _ := strings.Cut(a, "=")
	return opt == "--secret" || opt == "--secret-file"
}

func loadPolicy() (secrets.Policy, error) {
	path, err := cache.ConfigPath()
	if err != nil {
		return nil, err
	}
	return secrets.LoadPolicy(path)
}

func configPathOr(fallback string) string {
	if p, err := cache.ConfigPath(); err == nil {
		return p
	}
	return fallback
}

func approvals(harness string) func() (*secrets.Approvals, error) {
	return func() (*secrets.Approvals, error) {
		v, err := vault.New("approvals")
		if err != nil {
			return nil, err
		}
		return &secrets.Approvals{Vault: v, Harness: harness, Now: time.Now,
			Lock: func() (func(), error) { return cache.Lock("approvals-" + harness) }}, nil
	}
}

// secureName is what dialogs call the OS credential store.
func secureName() string {
	if runtime.GOOS == "darwin" {
		return "the Keychain"
	}
	return "the keyring"
}

func harnessLabel(harness string) string {
	if harness == "codex" {
		return "Codex"
	}
	return "Claude Code"
}

// currentSession is the harness session this psudo was started from.
func currentSession(harness string) (secrets.Session, bool) {
	return secrets.DetectSession(harness, os.Getenv, proc.Ancestors())
}

// sessionPlace keeps values for the current session only. It is nil when
// psudo was not started from a harness session it can identify.
func sessionPlace(harness string) secrets.Place {
	s, ok := currentSession(harness)
	if !ok {
		return nil
	}
	v, err := vault.New("session")
	if err != nil {
		return nil
	}
	return secrets.SessionPlace(v, s, harnessLabel(harness))
}

// projectGit is git with a fixed environment: nothing the caller sets
// (GIT_DIR, GIT_CONFIG_GLOBAL, HOME) changes what it reports.
func projectGit() envfile.Git {
	path := sysbin.Find("git")
	if path == "" {
		return nil
	}
	return envfile.ExecGit{Path: path, Env: cache.Identity([]string{"PATH=" + strings.Join(sysbin.Dirs, ":"),
		"LANG=C", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0"})}
}

// projectPlace is the git-ignored env file of the project in dir, or nil.
func projectPlace(dir string) secrets.Place {
	git := projectGit()
	if git == nil {
		return nil
	}
	return secrets.ProjectPlace(envfile.Find(dir, git), git)
}

// endSession handles the SessionEnd hook: it forgets what was kept for the
// session that ends, and for every session whose harness is gone.
func endSession(stdin io.Reader, harness string) error {
	var event struct {
		ID string `json:"session_id"`
	}
	if stdin != nil {
		json.NewDecoder(io.LimitReader(stdin, 1<<20)).Decode(&event) // without an id, only dead sessions are cleared
	}
	return forget(harness, event.ID)
}

// forget is forgetSessions; tests replace it so that they never touch the real
// credential store.
var forget = forgetSessions

// forgetSessions removes the secrets of the session with this id ("" for
// none) and of sessions whose harness process no longer exists.
func forgetSessions(harness, id string) error {
	v, err := vault.New("session")
	if err != nil {
		return nil // no credential store on this system: nothing was kept
	}
	_, err = secrets.EndSession(v, harness, id, proc.Alive)
	return err
}

func runSecrets(harness, exe, host string, uses []secrets.Use, argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "psudo: cannot determine the current folder")
		return runner.ExitUsage
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	r := &secrets.Runner{
		Harness:    harness,
		Title:      titleFor(harness, "Secret request"),
		Policy:     loadPolicy,
		Vault:      func() (vault.Vault, error) { return vault.New("secret") },
		SecureName: secureName(),
		Session:    func() secrets.Place { return sessionPlace(harness) },
		Project:    projectPlace,
		Approvals:  approvals(harness),
		Ask:        prompt.System().Ask,
		AddRules: func(rules map[string]secrets.Rule) error {
			path, err := cache.ConfigPath()
			if err != nil {
				return err
			}
			return secrets.AddRules(path, rules)
		},
		ConfigPath: configPathOr("config.json"),
		Choose:     prompt.System().Choose,
		Find:       sysbin.Find,
		Environ:    os.Environ(),
		TempRoot:   cache.LockRoot(),
		SSH: &runner.Runner{SSH: sysbin.Find("ssh"), SSHEnv: runner.SSHEnv(os.Environ()),
			ControlDir: runner.ControlDir, Askpass: exe, Stderr: stderr},
		Stdin:   stdin,
		Stdout:  stdout,
		Stderr:  stderr,
		Signals: sigs,
	}
	return r.Run(context.Background(), secrets.Request{Host: host, Dir: dir, Uses: uses, Argv: argv})
}

// secretAdmin handles --secret-set, --secret-import, --secret-list and
// --secret-delete.
func secretAdmin(name, value string, stdin io.Reader, stdout, stderr io.Writer) int {
	if name == "secret-list" {
		if value != "" {
			fmt.Fprintln(stderr, "psudo: --secret-list takes no value")
			return runner.ExitUsage
		}
	} else if !secrets.ValidKey(value) {
		fmt.Fprintf(stderr, "psudo: --%s=<name>: secret names use a-z, 0-9, _ and - (up to 63 characters); "+
			"<name>@<ssh host> is the secret of one host\n", name)
		return runner.ExitUsage
	}
	v, err := vault.New("secret")
	if err != nil {
		fmt.Fprintln(stderr, "psudo: "+err.Error())
		return secrets.ExitStore
	}
	harness := harnessOf(executable())
	cmd := &secretCmd{harness: harness, vault: v, ui: prompt.System(), policy: loadPolicy,
		stdin: stdin, stdout: stdout, stderr: stderr}
	if s, ok := currentSession(harness); ok {
		if sv, err := vault.New("session"); err == nil {
			cmd.sessionNames = func() ([]string, error) { return secrets.SessionNames(sv, s) }
			cmd.forget = func(name string) error { return secrets.ForgetSession(sv, s, name) }
		}
	}
	return cmd.run(name, value)
}

// secretCmd is one secret administration command, with its dependencies.
type secretCmd struct {
	harness string
	vault   vault.Vault
	ui      interface {
		Ask(context.Context, prompt.Request) ([]byte, error)
		Choose(context.Context, prompt.Choice) (int, error)
	}
	policy func() (secrets.Policy, error)
	// sessionNames lists the secrets kept for the current session, and forget
	// removes one. Both are nil when psudo was not started from a session.
	sessionNames   func() ([]string, error)
	forget         func(name string) error
	stdin          io.Reader
	stdout, stderr io.Writer
}

// inSession returns the secrets kept for the current session.
func (c *secretCmd) inSession() (map[string]bool, error) {
	set := map[string]bool{}
	if c.sessionNames == nil {
		return set, nil
	}
	names, err := c.sessionNames()
	for _, n := range names {
		set[n] = true
	}
	return set, err
}

func (c *secretCmd) storeFail() int {
	fmt.Fprintln(c.stderr, "psudo: the OS credential store is unavailable")
	return secrets.ExitStore
}

func (c *secretCmd) confirm(text, action string) int {
	choice, err := c.ui.Choose(context.Background(), prompt.Choice{Title: titleFor(c.harness, "Secrets"),
		Text: text, Buttons: []string{"Cancel", action}})
	if errors.Is(err, prompt.ErrNoProvider) {
		fmt.Fprintln(c.stderr, "psudo: no dialog is available to confirm this")
		return runner.ExitNoProvider
	}
	if err != nil || choice != 1 {
		fmt.Fprintln(c.stderr, "psudo: cancelled; nothing was changed")
		return runner.ExitCancelled
	}
	return 0
}

func (c *secretCmd) run(name, value string) int {
	switch name {
	case "secret-list":
		return c.list()
	case "secret-delete":
		return c.remove(value)
	}
	return c.store(name == "secret-import", value)
}

func (c *secretCmd) list() int {
	stored, err := c.vault.List()
	if err != nil {
		return c.storeFail()
	}
	session, err := c.inSession()
	if err != nil {
		return c.storeFail()
	}
	lasting := map[string]bool{}
	var names []string
	for _, s := range stored {
		// A host's own secret is kept under a name with the host in hex.
		if n, ok := secrets.KeyOfStore(s); ok {
			names = append(names, n)
			lasting[n] = true
		}
	}
	for n := range session {
		if !lasting[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	policy, perr := c.policy()
	for _, n := range names {
		// A third column says when the value is kept for this session only.
		kept := ""
		if session[n] && !lasting[n] {
			kept = "\tthis session only"
		}
		rule, ok := policy[n]
		switch {
		case perr != nil:
			fmt.Fprintf(c.stdout, "%s\t(config.json is invalid: %v)%s\n", n, perr, kept)
		case !ok:
			fmt.Fprintf(c.stdout, "%s\t(no rule in config.json yet; psudo offers one on first use)%s\n", n, kept)
		default:
			var where []string
			if rule.Local {
				where = append(where, "this computer")
			}
			where = append(where, rule.SSHHosts...)
			fmt.Fprintf(c.stdout, "%s\tcommands: %s; hosts: %s%s\n", n, strings.Join(rule.Commands, ", "), strings.Join(where, ", "), kept)
		}
	}
	return 0
}

func (c *secretCmd) remove(name string) int {
	ok, err := c.vault.Has(secrets.StoreName(name))
	if err != nil {
		return c.storeFail()
	}
	session, err := c.inSession()
	if err != nil {
		return c.storeFail()
	}
	if !ok && !session[name] {
		fmt.Fprintf(c.stderr, "psudo: no secret named %q is stored\n", name)
		return 1
	}
	if code := c.confirm("Delete the stored secret \""+name+"\"?\n\nThis cannot be undone.", "Delete"); code != 0 {
		return code
	}
	if ok && c.vault.Delete(secrets.StoreName(name)) != nil {
		return c.storeFail()
	}
	if session[name] && c.forget(name) != nil {
		return c.storeFail()
	}
	fmt.Fprintf(c.stdout, "psudo: deleted secret %s\n", name)
	return 0
}

func (c *secretCmd) store(fromStdin bool, name string) int {
	exists, err := c.vault.Has(secrets.StoreName(name))
	if err != nil {
		return c.storeFail()
	}
	var value []byte
	defer func() { clear(value) }()
	if fromStdin {
		data, err := io.ReadAll(io.LimitReader(c.stdin, secrets.MaxValue+2))
		trimmed := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		clear(data)
		if err != nil || len(trimmed) > secrets.MaxValue {
			fmt.Fprintf(c.stderr, "psudo: the value must be at most %d bytes; nothing was stored\n", secrets.MaxValue)
			return 1
		}
		if trimmed == "" {
			fmt.Fprintln(c.stderr, "psudo: --secret-import read an empty value from stdin; nothing was stored")
			return 1
		}
		value = []byte(trimmed)
	}
	switch {
	case exists:
		if code := c.confirm("Replace the stored secret \""+name+"\" with a new value?", "Replace"); code != 0 {
			return code
		}
	case fromStdin:
		// The value comes from whoever ran the command, not from a dialog.
		// Without this question the agent could store a value of its own
		// under a name the user later trusts as theirs.
		if code := c.confirm("Store a new secret \""+name+"\"?\n\nIts value was given to psudo by the command that "+
			"started it, not typed into a dialog. Store it only if you ran that command or asked for it.", "Store"); code != 0 {
			return code
		}
	}
	if !fromStdin {
		v, err := c.ui.Ask(context.Background(), prompt.Request{Title: titleFor(c.harness, "New secret"),
			Text: "Enter the value for the secret \"" + name + "\".\n\npsudo stores it in the OS credential " +
				"store and never shows it to the agent.", Timeout: 3 * prompt.DefaultTimeout})
		switch {
		case errors.Is(err, prompt.ErrNoProvider):
			fmt.Fprintln(c.stderr, "psudo: no dialog is available; pipe the value into psudo --secret-import="+name+" instead")
			return runner.ExitNoProvider
		case err != nil:
			fmt.Fprintln(c.stderr, "psudo: cancelled; nothing was stored")
			return runner.ExitCancelled
		}
		value = v
	}
	if err := c.vault.Put(secrets.StoreName(name), value); err != nil {
		return c.storeFail()
	}
	fmt.Fprintf(c.stdout, "psudo: stored secret %s\n", name)
	if policy, err := c.policy(); err == nil {
		if _, ok := policy[name]; !ok {
			fmt.Fprintf(c.stdout, "psudo: add a rule for it under \"secrets\" in config.json before it can be used, for example\n"+
				"  \"%s\": { \"commands\": [\"<program>\"] }\n", name)
		}
	}
	return 0
}
