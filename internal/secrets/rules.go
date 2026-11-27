package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/jsonedit"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
)

// SuggestedRule is the rule psudo offers when a request names a secret that
// has no rule: only this program, only this host. Like any rule it does not
// ask before each use; the dialog in which the user accepts it is the question.
//
// The rule also names the variables the request puts the secret called name
// in, so that later requests cannot move it to another variable.
func SuggestedRule(req Request, name string) Rule {
	// An interpreter runs whatever code it is given, so naming it in a rule
	// says nothing about what happens to the secret. For one, the suggested
	// rule asks before each use, and the dialog shows the whole command.
	r := Rule{Commands: []string{req.Argv[0]}, Local: req.Host == "", Confirm: RunsCode(req.Argv[0])}
	if req.Host != "" {
		r.SSHHosts = []string{req.Host}
	}
	for _, u := range req.Uses {
		if u.Name == name && !slices.Contains(r.Vars, u.Var) {
			r.Vars = append(r.Vars, u.Var)
		}
	}
	return r
}

// AddRules writes rules into the "secrets" object of the config file at
// path, keeping the order and formatting of everything else. Existing rules
// with the same names are not replaced.
func AddRules(path string, rules map[string]Rule) error {
	root := jsonedit.NewObject()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		v, err := jsonedit.Parse(data)
		obj, ok := v.(*jsonedit.Object)
		if err != nil || !ok {
			return fmt.Errorf("%s is not a JSON object", path)
		}
		root = obj
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	secrets := jsonedit.NewObject()
	if v, ok := root.Get("secrets"); ok {
		obj, ok := v.(*jsonedit.Object)
		if !ok {
			return fmt.Errorf("%s: secrets is not an object", path)
		}
		secrets = obj
	}
	for _, name := range sortedNames(rules) {
		if _, exists := secrets.Get(name); exists {
			return fmt.Errorf("%s already has a rule for %q", path, name)
		}
		r := rules[name]
		entry := jsonedit.NewObject()
		cmds := make([]any, len(r.Commands))
		for i, c := range r.Commands {
			cmds[i] = c
		}
		entry.Set("commands", cmds)
		if len(r.Vars) > 0 {
			vars := make([]any, len(r.Vars))
			for i, v := range r.Vars {
				vars[i] = v
			}
			entry.Set("vars", vars)
		}
		// A rule for one host's secret names its host in the key.
		_, host := SplitKey(name)
		if !r.Local && host == "" {
			entry.Set("local", false)
		}
		if len(r.SSHHosts) > 0 && host == "" {
			hosts := make([]any, len(r.SSHHosts))
			for i, h := range r.SSHHosts {
				hosts[i] = h
			}
			entry.Set("ssh_hosts", hosts)
		}
		if r.Confirm {
			entry.Set("confirm", true)
		}
		secrets.Set(name, entry)
	}
	root.Set("secrets", secrets)
	out, err := jsonedit.Marshal(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// merge returns p with extra added.
func merge(p Policy, extra map[string]Rule) Policy {
	out := Policy{}
	for k, v := range p {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func ruleNote(path, name string, r Rule) string {
	where := "on this computer"
	if !r.Local {
		where = "on " + strings.Join(r.SSHHosts, ", ")
	}
	if path == "" {
		path = "config.json"
	}
	// The rule gets lines of its own, so a long program path cannot push the
	// rest of it out of a dialog that is shortened to fit.
	note := "This also adds a rule to " + shquote.VisibleLine(path) + ":\n" + strings.Join(r.Commands, ", ") +
		"\nmay use \"" + name + "\" as " + strings.Join(r.Vars, ", ") + " " + where + ".\n"
	if r.Confirm {
		return note + "This program runs whatever code it is given, so psudo asks before each use and shows the command. " +
			"Any other program or variable is refused."
	}
	return note + "From then on psudo gives it the secret without asking again, as long as the program file stays the same; " +
		"any other program or variable is refused."
}
