package secrets

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/envfile"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/prompt"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/runner"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/sysbin"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/vault"
)

// Exit codes from docs/secrets.md §5.2.
const (
	ExitNotAllowed = 253
	ExitStore      = 254
)

// RemoteScript is fixed text. The marker, the number of secrets, each
// secret's kind and variable name, and the command arrive as positional
// parameters; the values arrive base64-encoded, one per line, on stdin.
// Files go into a private mktemp -d directory that the EXIT trap removes.
// The script first reports "<marker> ready": psudo sends the values only after
// that line, so they never reach a host that is not running this script (a
// forced command, a login shell that is not a POSIX shell, a startup file
// that reads stdin). After the last value, stdin is closed and the line
// "<marker> ok" reports that every secret was delivered.
const RemoteScript = `m=$1; n=$2; shift 2; d=; ` +
	`trap '[ -z "$d" ] || rm -rf "$d"' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; ` +
	`printf '%s ready\n' "$m"; ` +
	`i=0; while [ "$i" -lt "$n" ]; do k=$1; v=$2; shift 2; IFS= read -r b || exit 97; ` +
	`if [ "$k" = file ]; then if [ -z "$d" ]; then d=$(umask 077; mktemp -d) || exit 97; fi; ` +
	`(umask 077; printf '%s' "$b" | base64 -d > "$d/$v") || exit 97; export "$v=$d/$v"; ` +
	`else x=$(printf '%s' "$b" | base64 -d && echo .) || exit 97; x=${x%.}; export "$v=$x"; x=; fi; ` +
	`b=; i=$((i+1)); done; exec </dev/null; printf '%s ok\n' "$m"; "$@"; exit $?`

// Runner holds every dependency of a secret run so tests can substitute fakes.
type Runner struct {
	Harness string
	Title   string // dialog title, such as "Secret request (Claude Code)"

	Policy func() (Policy, error)
	// Vault is the OS credential store, one of the places a value can be
	// kept. SecureName is its name in dialogs, such as "the Keychain".
	Vault      func() (vault.Vault, error)
	SecureName string
	// Session returns where a value is kept for this harness session only,
	// or nil when psudo cannot tell which session it was started from.
	Session func() Place
	// Project returns the git-ignored env file of the project in dir, or nil
	// when the project has none.
	Project   func(dir string) Place
	Approvals func() (*Approvals, error) // remembered approvals and the approved rules
	// ConfigPath is shown when the user is asked to approve changed rules.
	ConfigPath string
	// AddRules writes new rules into the config file.
	AddRules func(map[string]Rule) error
	Choose   prompt.Chooser
	// Ask shows a hidden-input dialog: the value of a secret that is not stored yet.
	Ask  prompt.Asker
	Find func(string) string

	Environ  []string // the caller's environment; only a fixed set passes
	TempRoot string   // where local secret files go; "" means os.TempDir()

	// SSH carries the SSH settings and login logic of the sudo path.
	SSH *runner.Runner

	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Signals        <-chan os.Signal

	// beforeStart, in tests, runs between the check of the program file and
	// the start of the program.
	beforeStart func()
}

func (r *Runner) fail(format string, args ...any) {
	fmt.Fprintf(r.Stderr, "psudo: "+format+"\n", args...)
}

// stores are the places the values of one request can come from, and what has
// been found in them so far.
type stores struct {
	session, secure, project Place
	// from is the place that has each secret; a secret that is in none of
	// them is missing from the map.
	from map[string]Place
	// once holds a value the user entered for this command only.
	once map[string][]byte
}

// find looks for name: the session first, then the OS credential store, then
// the project's env file. The env file comes last because the agent can
// write it: a line added there must not replace a value the user stored.
func (s *stores) find(name string) error {
	p, err := lookup([]Place{s.session, s.secure, s.project}, name)
	if err == nil && p != nil {
		s.from[name] = p
	}
	return err
}

func (s *stores) value(name string) ([]byte, error) {
	if b, ok := s.once[name]; ok {
		return b, nil
	}
	if p := s.from[name]; p != nil {
		return p.Get(name)
	}
	return nil, nil
}

// Message is the dialog body for req.
func Message(req Request) string { return message(req, nil) }

// message is Message with the place each value comes from, for the secrets
// that are in from.
func message(req Request, from map[string]Place) string {
	var b strings.Builder
	b.WriteString("Use secrets:\n")
	for _, u := range req.Uses {
		where := ""
		if p := from[u.Name]; p != nil {
			where = "  (from " + shquote.VisibleLine(p.Name()) + ")"
		}
		if u.File {
			fmt.Fprintf(&b, "  %s  as a file in %s%s\n", u.Name, u.Var, where)
		} else {
			fmt.Fprintf(&b, "  %s  as %s%s\n", u.Name, u.Var, where)
		}
	}
	host := req.Host
	if host == "" {
		host = "this computer"
	}
	b.WriteString("\nHost: " + shquote.VisibleLine(host) + "\n")
	if req.Host == "" {
		// The folder name is the caller's: kept on one line, it cannot pose
		// as the Command line below it.
		b.WriteString("Folder: " + shquote.VisibleLine(req.Dir) + "\n")
	}
	b.WriteString("Command:\n" + shquote.Visible(shquote.Join(req.Argv)) + "\n\n")
	b.WriteString("Only this command receives the values, but it can send them anywhere it chooses.")
	return b.String()
}

// Run checks, approves and runs req, and returns the exit code.
func (r *Runner) Run(ctx context.Context, req Request) int {
	policy, err := r.Policy()
	if err != nil {
		r.fail("NOT ALLOWED: %v. No secret was used and the command was not run.", err)
		return ExitNotAllowed
	}
	// A secret with no rule gets the narrowest rule for this request, offered
	// to the user below. Everything else in Check still applies to it.
	newRules := map[string]Rule{}
	for _, n := range Names(req.Uses) {
		if _, ok := policy[n]; !ok && len(req.Argv) > 0 {
			newRules[n] = SuggestedRule(req, n)
		}
	}
	effective := merge(policy, newRules)
	decision, err := Check(effective, req, r.Find)
	if err != nil {
		r.fail("NOT ALLOWED: %v. The command was not run.", err)
		return ExitNotAllowed
	}
	// Whether the program is an interpreter is judged by the file that will
	// run, not only by the name it was called by: a link called deploy-tool
	// that points at python3 is python3. A rule for an interpreter asks
	// before each use.
	if req.Host == "" && len(newRules) > 0 && interpreterFile(decision.Path, r.Find) {
		for n, rule := range newRules {
			rule.Confirm = true
			newRules[n] = rule
		}
		effective = merge(policy, newRules)
		if decision, err = Check(effective, req, r.Find); err != nil {
			r.fail("NOT ALLOWED: %v. The command was not run.", err)
			return ExitNotAllowed
		}
	}
	// A suggested rule is written to the config file, so it has to be a rule
	// the file may contain.
	for _, n := range sortedNames(newRules) {
		if err := newRules[n].Validate(); err != nil {
			r.fail("NOT ALLOWED: no rule can be added for secret %q: %v. The command was not run.", n, err)
			return ExitNotAllowed
		}
	}
	v, err := r.Vault()
	if err != nil {
		r.fail("the OS credential store is unavailable. The command was not run.")
		return ExitStore
	}
	st := &stores{secure: Secure(v, r.SecureName), from: map[string]Place{}, once: map[string][]byte{}}
	if r.Session != nil {
		st.session = r.Session()
	}
	if r.Project != nil {
		st.project = r.Project(req.Dir)
	}
	for _, n := range Names(req.Uses) {
		if err := st.find(n); err != nil {
			r.fail("could not read the OS credential store. The command was not run.")
			return ExitStore
		}
	}
	// A value from the project's env file needs no rule, and psudo writes none
	// for it: the file is plain text the agent can read, so a rule would
	// protect nothing. It must not leave a rule behind either. A rule added
	// without a dialog, for a name the agent put in that file, would later
	// cover a real value the user stores under the same name. (A rule that is
	// already in the file for the name still applies, as a restriction.)
	fromProject := func(n string) bool { return st.project != nil && st.from[n] == st.project }
	var fromFile, others []string
	for _, n := range Names(req.Uses) {
		if fromProject(n) {
			delete(newRules, n)
			fromFile = append(fromFile, n)
		} else {
			others = append(others, n)
		}
	}
	needRules := len(others) > 0
	// The agent can write the env file, and it picks the variable each value
	// goes into. Together that is a way to set any variable of the program:
	// GIT_SSH_COMMAND, NODE_OPTIONS, a config file path. Alone that is
	// nothing the agent could not do by running the program itself. Next to
	// a stored secret it is a way to make the allowed program hand that
	// secret over. So the two never share a command, and this is refused
	// before any dialog. No list of dangerous variable names could replace
	// this: every tool has its own.
	if len(fromFile) > 0 && len(others) > 0 {
		r.fail("NOT ALLOWED: %s comes from %s, a file the agent can write, so it cannot share a command with a stored secret (%s). "+
			"Let the program read the env file itself, or keep that value in the session or the %s. The command was not run.",
			strings.Join(fromFile, ", "), st.project.Name(), strings.Join(others, ", "), strings.TrimPrefix(st.secure.Name(), "the "))
		return ExitNotAllowed
	}
	approvals, err := r.Approvals()
	if err != nil {
		r.fail("the OS credential store is unavailable. The command was not run.")
		return ExitStore
	}
	// Rules already in the file may have been edited by the agent: they need
	// the user's approval before they open a stored secret to a program, and
	// before anything is added to them.
	if needRules {
		if code, ok := r.approveRules(ctx, approvals, policy); !ok {
			return code
		}
	}
	// A secret that is in none of the places is asked for, and a stored
	// secret with no rule is offered, in a dialog that shows the whole
	// request. Answering it approves this run.
	values := map[string][]byte{}
	defer func() {
		for _, b := range values {
			clear(b)
		}
		for _, b := range st.once {
			clear(b)
		}
	}()
	covered := false
	for _, n := range Names(req.Uses) {
		rule, adding := newRules[n]
		if st.from[n] != nil && !adding {
			continue
		}
		code, ok := r.obtain(ctx, st, req, n, adding, rule)
		if !ok {
			return code
		}
		covered = true
		if fromProject(n) {
			delete(newRules, n) // the user chose the env file for it: no rule
		}
	}
	if len(newRules) > 0 {
		if err := r.AddRules(newRules); err != nil {
			r.fail("could not add the rule to config.json (%v). The command was not run.", err)
			return ExitStore
		}
		if err := approvals.ApproveRules(merge(policy, newRules)); err != nil {
			r.fail("could not record the approved rules. The command was not run.")
			return ExitStore
		}
	}
	if !covered {
		if code, ok := r.approve(ctx, approvals, req, decision, st.from); !ok {
			return code
		}
	}

	for _, n := range Names(req.Uses) {
		b, err := st.value(n)
		if err != nil || len(b) == 0 {
			r.fail("could not read the value of secret %q. The command was not run.", n)
			return ExitStore
		}
		if len(b) > MaxValue {
			r.fail("the value of secret %q is too large. The command was not run.", n)
			return ExitStore
		}
		values[n] = b
	}
	byName := map[string][][]byte{}
	for _, u := range req.Uses {
		byName[u.Name] = append(byName[u.Name], Patterns(u.Name, values[u.Name], u.File)...)
	}
	stdout := NewRedactor(r.Stdout, byName)
	stderr := NewRedactor(r.Stderr, byName)
	defer stdout.Flush()
	defer stderr.Flush()
	if req.Host == "" {
		// Last of all, right before the program starts: is it still the
		// program the user allowed?
		identity, code, ok := r.pinProgram(ctx, approvals, req, decision, st, fromProject)
		if !ok {
			return code
		}
		return r.local(ctx, req, decision.Path, identity, values, stdout, stderr)
	}
	return r.remote(ctx, req, values, stdout, stderr)
}

// pinProgram checks that the program about to receive stored secrets is the
// file it was when the user allowed it (see pins.go), and asks when it is
// not. The first use of a program is remembered without a question.
//
// It returns the identity of the file it read, which local compares once more
// right before the start ("" when nothing was checked).
func (r *Runner) pinProgram(ctx context.Context, a *Approvals, req Request, d Decision, st *stores, fromProject func(string) bool) (string, int, bool) {
	var names []string
	for _, n := range Names(req.Uses) {
		if !fromProject(n) { // a value from the env file is nothing the agent could not read
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", 0, true
	}
	before, err := fileIdentity(d.Path)
	if err != nil {
		r.fail("could not read %s to check that it is the program you allowed (%v). The command was not run.", d.Path, err)
		return "", ExitStore, false
	}
	sum, err := fileSum(d.Path)
	if err != nil {
		r.fail("could not read %s to check that it is the program you allowed (%v). The command was not run.", d.Path, err)
		return "", ExitStore, false
	}
	if after, err := fileIdentity(d.Path); err != nil || after != before {
		r.fail("NOT ALLOWED: %s changed while psudo was checking it. The command was not run.", d.Path)
		return "", ExitNotAllowed, false
	}
	pins, err := a.Pins()
	if err != nil {
		r.fail("could not read the OS credential store. The command was not run.")
		return "", ExitStore, false
	}
	update := map[string]string{}
	var changed []string
	for _, n := range names {
		key := pinKey(n, d.Entry[n])
		old, known := pins[key]
		if known && old == sum {
			continue
		}
		update[key] = sum
		if known {
			changed = append(changed, "\""+n+"\"")
		}
	}
	if len(changed) > 0 {
		_, code, ok := r.ask(ctx, prompt.Choice{Title: r.retitle("Program changed"),
			Text: "The program that may use " + strings.Join(changed, ", ") + " is not the file it was when you allowed it:\n" +
				shquote.VisibleLine(d.Path) + "\n\nThat is normal after the program was updated. It also happens when " +
				"someone, the agent included, has edited or replaced it.\n\n" + message(req, st.from),
			Buttons: []string{"Deny", "Allow this version"}},
			"the program has changed since the user allowed it, and the user did not allow the new version (or the dialog timed out).")
		if !ok {
			return "", code, false
		}
	}
	if len(update) > 0 {
		if err := a.SetPins(update); err != nil {
			r.fail("could not remember the program in the OS credential store. The command was not run.")
			return "", ExitStore, false
		}
	}
	return before, 0, true
}

func (r *Runner) retitle(what string) string {
	return strings.Replace(r.Title, "Secret request", what, 1)
}

// obtain asks for the value of a secret that is in none of the places, or for
// permission to add a rule for one that is, and keeps the answer.
func (r *Runner) obtain(ctx context.Context, st *stores, req Request, name string, adding bool, rule Rule) (int, bool) {
	note := ""
	if adding {
		note = "\n\n" + ruleNote(r.ConfigPath, name, rule)
	}
	if st.from[name] != nil {
		_, code, ok := r.ask(ctx, prompt.Choice{Title: r.Title,
			Text:    "The stored secret \"" + name + "\" has no rule yet.\n\n" + message(req, st.from) + note,
			Buttons: []string{"Deny", "Allow and add rule"}},
			"the user did not allow this use of the secret (or the dialog timed out).")
		return code, ok
	}
	if r.Ask == nil {
		r.fail("NOT ALLOWED: no secret named %q is stored. The command was not run.", name)
		return ExitNotAllowed, false
	}
	value, err := r.Ask(ctx, prompt.Request{Title: r.retitle("Secret needed"), Timeout: 3 * prompt.DefaultTimeout,
		Text: "psudo has no value for the secret \"" + name + "\". Type or paste it to run this command. " +
			"psudo then asks where to keep it; unless you choose otherwise, it is not kept beyond this session.\n\n" +
			message(req, st.from) + note})
	defer clear(value)
	switch {
	case errors.Is(err, prompt.ErrNoProvider):
		r.fail("no dialog is available to enter the secret (a logged-in desktop with osascript, zenity or kdialog is required)")
		return runner.ExitNoProvider, false
	case err != nil:
		r.fail("DENIED: the user did not enter the secret %q (or the dialog timed out). The command was not run.", name)
		return runner.ExitCancelled, false
	case len(value) > MaxValue:
		r.fail("the value entered for %q is too large. The command was not run.", name)
		return ExitStore, false
	}
	return r.keep(ctx, st, name, value)
}

// saver is a place that cannot take every secret: an env file has no
// variable for a name that starts with a digit.
type saver interface{ CanSave(name string) bool }

// keep asks where the value just entered for name is kept, and puts it there.
//
// The first button is the default, the one Return, a closed dialog
// and a timeout choose: the session, so that nothing outlives it unless the
// user says so. When psudo cannot tell which session it runs in, the first
// button keeps the value for this command only.
func (r *Runner) keep(ctx context.Context, st *stores, name string, value []byte) (int, bool) {
	options := []Place{st.session}
	labels := []string{"This session only"}
	var text strings.Builder
	text.WriteString("Where should psudo keep \"" + name + "\"?\n")
	if st.session != nil {
		text.WriteString("\nThis session only: " + st.session.Note(name) + "\n")
	} else {
		labels[0] = "Only this command"
		text.WriteString("\nOnly this command: psudo cannot tell which session this is, so it uses the value for this " +
			"command and then forgets it.\n")
	}
	for _, p := range []Place{st.project, st.secure} {
		if p == nil {
			continue
		}
		if s, ok := p.(saver); ok && !s.CanSave(name) {
			continue
		}
		short := strings.TrimPrefix(p.Name(), "the ")
		options = append(options, p)
		labels = append(labels, "Save in "+short)
		text.WriteString("\n" + shquote.VisibleLine(short) + ": " + p.Note(name) + "\n")
	}
	choice := 0
	if len(options) > 1 {
		// A dialog that cannot show buttons, or that fails, leaves the default.
		if c, err := r.Choose(ctx, prompt.Choice{Title: r.retitle("Keep the secret?"), Text: text.String(),
			Buttons: labels, Timeout: prompt.DefaultTimeout}); err == nil && c > 0 && c < len(options) {
			choice = c
		}
	}
	place := options[choice]
	if place == nil {
		st.once[name] = append([]byte(nil), value...)
		return 0, true
	}
	if err := place.Put(name, value); err != nil {
		r.fail("could not keep the secret %q in %s (%v). The command was not run.", name, place.Name(), err)
		return ExitStore, false
	}
	st.from[name] = place
	return 0, true
}

// RulesMessage is the dialog body that asks the user to approve rules.
// approved holds the hash of each rule the user approved last; with it, the
// dialog shows only the rules that are new or changed and names the removed
// ones, so what is being approved fits in the dialog. Without it (nil), it
// shows every rule.
func RulesMessage(path string, p Policy, approved map[string]string) string {
	var b strings.Builder
	b.WriteString("The secret rules in " + shquote.VisibleLine(path) + " are new or have changed. psudo uses them only after you approve them.\n")
	names := sortedNames(p)
	var shown, removed []string
	label := map[string]string{}
	for _, name := range names {
		switch h, ok := approved[name]; {
		case approved == nil:
			shown = append(shown, name)
		case !ok:
			shown, label[name] = append(shown, name), " (new)"
		case h != ruleHash(p[name]):
			shown, label[name] = append(shown, name), " (changed)"
		}
	}
	for name := range approved {
		if _, ok := p[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	if approved != nil && len(shown) == 0 && len(removed) == 0 {
		shown = names // nothing differs rule by rule: show them all
	}
	for _, name := range shown {
		rule := p[name]
		var hosts []string
		if rule.Local {
			hosts = append(hosts, "this computer")
		}
		hosts = append(hosts, rule.SSHHosts...)
		if len(hosts) == 0 {
			hosts = []string{"nowhere"}
		}
		// Not asking is the default: the rule itself is what lets a program
		// have the secret. A rule can ask before each use with "confirm": true.
		ask := "these programs get it without a dialog"
		switch {
		case rule.Confirm && rule.RememberSeconds > 0:
			ask = fmt.Sprintf("asks before each use, can remember for %d min", (rule.RememberSeconds+59)/60)
		case rule.Confirm:
			ask = "asks before each use"
		}
		vars := strings.Join(rule.Vars, ", ")
		if vars == "" {
			vars, _ = envfile.Key(name)
		}
		fmt.Fprintf(&b, "\n%s%s\n  commands: %s\n  as: %s\n  hosts: %s\n  %s\n", name, label[name],
			strings.Join(rule.Commands, ", "), vars, strings.Join(hosts, ", "), ask)
	}
	if len(removed) > 0 {
		fmt.Fprintf(&b, "\nRemoved: %s\n", strings.Join(removed, ", "))
	}
	if n := len(names) - len(shown); n == 1 {
		b.WriteString("\n1 other rule is unchanged.\n")
	} else if n > 1 {
		fmt.Fprintf(&b, "\n%d other rules are unchanged.\n", n)
	}
	return b.String()
}

func sortedNames(p Policy) []string {
	var names []string
	for n := range p {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ask shows a choice and maps refusals to exit codes.
func (r *Runner) ask(ctx context.Context, c prompt.Choice, refused string) (int, int, bool) {
	c.Timeout = prompt.DefaultTimeout
	choice, err := r.Choose(ctx, c)
	switch {
	case errors.Is(err, prompt.ErrNoProvider):
		r.fail("no dialog is available to approve the secret (a logged-in desktop with osascript, zenity or kdialog is required)")
		return 0, runner.ExitNoProvider, false
	case err != nil || choice == 0:
		r.fail("DENIED: " + refused + " The command was not run.")
		return 0, runner.ExitCancelled, false
	}
	return choice, 0, true
}

func (r *Runner) approveRules(ctx context.Context, a *Approvals, p Policy) (int, bool) {
	// A file with no rules has nothing to approve, and psudo does not open a
	// dialog about it. No rule means no program may have a stored secret: one
	// has to be allowed in its own dialog, which shows the command.
	if len(p) == 0 {
		return 0, true
	}
	hash := RulesHash(p)
	ok, err := a.RulesApproved(hash)
	if err != nil {
		r.fail("could not read the OS credential store. The command was not run.")
		return ExitStore, false
	}
	if ok {
		return 0, true
	}
	before, err := a.ApprovedRules()
	if err != nil {
		r.fail("could not read the OS credential store. The command was not run.")
		return ExitStore, false
	}
	_, code, ok := r.ask(ctx, prompt.Choice{Title: strings.Replace(r.Title, "Secret request", "Secret rules changed", 1),
		Text: RulesMessage(r.ConfigPath, p, before), Buttons: []string{"Deny", "Approve rules"}},
		"the user did not approve the changed secret rules (or the dialog timed out).")
	if !ok {
		return code, false
	}
	if err := a.ApproveRules(p); err != nil {
		r.fail("could not record the approved rules. The command was not run.")
		return ExitStore, false
	}
	return 0, true
}

func (r *Runner) approve(ctx context.Context, approvals *Approvals, req Request, d Decision, from map[string]Place) (int, bool) {
	if !d.Confirm {
		return 0, true
	}
	key := Key(r.Harness, req)
	if d.Remember > 0 {
		if ok, err := approvals.Has(key); err == nil && ok {
			return 0, true
		}
	}
	// The last line says what the buttons do: without it, "once" leaves the
	// user guessing whether a click is needed and what happens next time.
	buttons := []string{"Deny", "Allow once"}
	hint := "Allow once runs this command one time; psudo asks again for the next one. Deny runs nothing."
	if d.Remember > 0 {
		minutes := (d.Remember + 59) / 60
		buttons = append(buttons, fmt.Sprintf("Allow for %d min", minutes))
		hint = fmt.Sprintf("Allow once runs this command one time. Allow for %d min also runs the same command, in the same "+
			"folder, without asking until then. Deny runs nothing.", minutes)
	}
	choice, code, ok := r.ask(ctx, prompt.Choice{Title: r.Title, Text: message(req, from) + "\n\n" + hint, Buttons: buttons},
		"the user did not allow this use of the secret (or the dialog timed out).")
	if !ok {
		return code, false
	}
	if choice == 2 {
		if err := approvals.Add(key, time.Duration(d.Remember)*time.Second); err != nil {
			r.fail("warning: could not remember the approval; the command is running anyway")
		}
	}
	return 0, true
}

var keepEnv = map[string]bool{"TERM": true, "LANG": true, "TZ": true, "TMPDIR": true, "SSH_AUTH_SOCK": true,
	"DBUS_SESSION_BUS_ADDRESS": true}

// ChildEnv is the fixed environment of a local secret command (§5.4): PATH set
// to the trusted directories; HOME, USER and LOGNAME from the account
// database; a few variables from the caller; and the secret variables last.
//
// Nothing the caller sets may change which configuration the command loads,
// because the dialog does not show it. So HOME is never the caller's, and the
// XDG_* directories are not passed: with XDG_CONFIG_HOME pointing at a folder
// of its own, the caller could give git or gh a config that runs a program
// with the secret. Only XDG_RUNTIME_DIR passes, and only when it is the
// standard per-user directory.
func ChildEnv(environ []string, extra []string) []string {
	env := []string{"PATH=" + strings.Join(sysbin.Dirs, ":")}
	runtimeDir := fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", os.Getuid())
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if keepEnv[name] || strings.HasPrefix(name, "LC_") || kv == runtimeDir {
			env = append(env, kv)
		}
	}
	return append(cache.Identity(env), extra...)
}

func exitCode(state *os.ProcessState) int {
	if st, ok := state.Sys().(syscall.WaitStatus); ok && st.Signaled() {
		return 128 + int(st.Signal())
	}
	return state.ExitCode()
}

// start runs cmd and forwards signals to it until it exits.
func (r *Runner) start(cmd *exec.Cmd) (func() int, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	if r.Signals != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case sig := <-r.Signals:
					cmd.Process.Signal(sig)
				case <-done:
					return
				}
			}
		}()
	}
	return func() int {
		cmd.Wait()
		close(done)
		wg.Wait()
		return exitCode(cmd.ProcessState)
	}, nil
}

func (r *Runner) local(ctx context.Context, req Request, path, identity string, values map[string][]byte, stdout, stderr io.Writer) int {
	if ctx.Err() != nil {
		r.fail("interrupted; the command was not run")
		return runner.ExitCancelled
	}
	var extra []string
	var dir string
	for _, u := range req.Uses {
		if !u.File {
			extra = append(extra, u.Var+"="+string(values[u.Name]))
			continue
		}
		if dir == "" {
			d, err := os.MkdirTemp(r.TempRoot, "psudo-secret-")
			if err != nil {
				r.fail("could not create a private directory for secret files. The command was not run.")
				return ExitStore
			}
			dir = d
			defer os.RemoveAll(dir)
		}
		file := filepath.Join(dir, u.Var)
		if err := os.WriteFile(file, values[u.Name], 0o600); err != nil {
			r.fail("could not write the secret file for %s. The command was not run.", u.Var)
			return ExitStore
		}
		extra = append(extra, u.Var+"="+file)
	}
	cmd := exec.Command(path, req.Argv[1:]...)
	cmd.Args[0] = req.Argv[0]
	cmd.Env = ChildEnv(r.Environ, extra)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = r.Stdin, stdout, stderr
	if r.beforeStart != nil {
		r.beforeStart()
	}
	// The last look at the file: it must still be the one whose contents
	// were checked (see pins.go). Nothing else happens between this and the
	// start of the program.
	if identity != "" {
		if now, err := fileIdentity(path); err != nil || now != identity {
			r.fail("NOT ALLOWED: %s changed after psudo checked it. The command was not run.", path)
			return ExitNotAllowed
		}
	}
	wait, err := r.start(cmd)
	if err != nil {
		r.fail("could not start %s: %v", req.Argv[0], err)
		return 127
	}
	return wait()
}

// RemoteCommand builds the string ssh hands to the remote login shell.
func RemoteCommand(marker string, uses []Use, argv []string) string {
	args := []string{marker, fmt.Sprint(len(uses))}
	for _, u := range uses {
		kind := "env"
		if u.File {
			kind = "file"
		}
		args = append(args, kind, u.Var)
	}
	return "exec /bin/sh -c " + shquote.Quote(RemoteScript) + " psudo " + shquote.Join(append(args, argv...))
}

func (r *Runner) remote(ctx context.Context, req Request, values map[string][]byte, stdout, stderr io.Writer) int {
	s := r.SSH
	if s == nil || s.SSH == "" {
		r.fail("ssh is not installed")
		return runner.ExitSSHFailed
	}
	opts, ok := s.Connect(ctx, req.Host)
	if !ok {
		return runner.ExitSSHFailed
	}
	if ctx.Err() != nil {
		r.fail("interrupted; the command was not run")
		return runner.ExitCancelled
	}
	marker := runner.NewMarker()
	cmd := exec.Command(s.SSH, runner.SSHArgs(req.Host, RemoteCommand(marker, req.Uses, req.Argv), opts...)...)
	cmd.Env = s.SSHEnv
	cmd.Stderr = stderr
	stdin, err1 := cmd.StdinPipe()
	pipe, err2 := cmd.StdoutPipe()
	if err1 != nil || err2 != nil {
		r.fail("could not create pipes")
		return ExitStore
	}
	wait, err := r.start(cmd)
	if err != nil {
		r.fail("could not start ssh")
		return runner.ExitSSHFailed
	}
	// The values go out only after the script reports that it is the one
	// reading stdin. Anything else on the host (a forced command, a shell
	// that is not a POSIX shell, a startup file) gets no input from psudo.
	reader := bufio.NewReader(pipe)
	timer := time.AfterFunc(s.ReadyWait(), func() { cmd.Process.Kill() })
	status, overflow := runner.AwaitStatus(reader, marker, stdout)
	timer.Stop()
	sent := status == runner.StatusReady && !overflow
	if sent {
		for _, u := range req.Uses {
			line := []byte(base64.StdEncoding.EncodeToString(values[u.Name]) + "\n")
			stdin.Write(line)
			clear(line)
		}
	}
	stdin.Close()
	if sent {
		status, overflow = runner.AwaitStatus(reader, marker, stdout)
	}
	if !sent || overflow {
		cmd.Process.Kill()
	}
	io.Copy(stdout, reader)
	code := wait()
	if sent && status == "ok" {
		return code
	}
	if code == runner.ExitSSHFailed || overflow {
		r.fail("SSH FAILED: the connection to %s failed or returned unexpected output. The command was not run.", req.Host)
		return runner.ExitSSHFailed
	}
	if !sent {
		r.fail("%s did not start psudo's script, so no secret was sent (it needs a POSIX login shell that runs the command "+
			"it is given). The command was not run.", req.Host)
		return ExitStore
	}
	r.fail("could not deliver the secrets on %s (it needs /bin/sh, base64 -d and mktemp). The command was not run.", req.Host)
	return ExitStore
}
