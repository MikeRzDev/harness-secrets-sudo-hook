package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/prompt"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/runner"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/secrets"
)

// Only error paths are exercised here; a valid command would open a real dialog.
func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"-u", "root", "id"}, {"-H"}, {"-H", "-oProxyCommand=x", "id"},
		{"-H", "a b", "id"}, {"-H", "host"}, {"--"}, {"--bogus"}, {"--install=other"}, {"--hook=x"},
		{"--version", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

func TestVersionAndHelp(t *testing.T) {
	var out bytes.Buffer
	if run([]string{"--version"}, nil, &out, &out) != 0 || !strings.HasPrefix(out.String(), "psudo ") {
		t.Fatal(out.String())
	}
	out.Reset()
	if run([]string{"--help"}, nil, &out, &out) != 0 || !strings.Contains(out.String(), "-H <host>") {
		t.Fatal(out.String())
	}
}

func TestHookDispatch(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"sudo id"}}`)
	if run([]string{"--hook=claude-code"}, in, &out, &out) != 0 || !strings.Contains(out.String(), `"updatedInput"`) {
		t.Fatal(out.String())
	}
	out.Reset()
	in = strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"sudo -i"}}`)
	if run([]string{"--hook=claude-code"}, in, &out, &out) != 0 || !strings.Contains(out.String(), `"deny"`) {
		t.Fatal(out.String())
	}
}

// The session hooks forget what was kept for a session. The real cleanup would
// read the OS credential store, so the test replaces it.
func TestSessionHooksForgetSessionSecrets(t *testing.T) {
	var calls []string
	old := forget
	forget = func(harness, id string) error { calls = append(calls, harness+":"+id); return nil }
	defer func() { forget = old }()

	var out bytes.Buffer
	end := `{"session_id":"3f2a9c1e-5b7d-4e8a-9c0b-1d2e3f4a5b6c","hook_event_name":"SessionEnd","reason":"clear"}`
	if code := run([]string{"--hook=claude-code-session-end"}, strings.NewReader(end), &out, &out); code != 0 || out.Len() != 0 {
		t.Fatalf("exit %d %s", code, out.String())
	}
	if code := run([]string{"--hook=codex-session-end"}, strings.NewReader("not json"), &out, &out); code != 0 {
		t.Fatalf("exit %d %s", code, out.String())
	}
	want := []string{"claude-code:3f2a9c1e-5b7d-4e8a-9c0b-1d2e3f4a5b6c", "codex:"}
	if strings.Join(calls, " ") != strings.Join(want, " ") {
		t.Fatalf("calls %q", calls)
	}
}

func TestHarnessFromInstallLocation(t *testing.T) {
	for path, want := range map[string]string{"/h/.codex/root-hook/psudo": "codex",
		"/h/.claude/hooks/psudo": "claude-code", "/usr/local/bin/psudo": "claude-code"} {
		if got := harnessOf(path); got != want {
			t.Errorf("%s: %s", path, got)
		}
	}
}

func TestAskpassAnswersLoginPromptsAndRefusesConfirmations(t *testing.T) {
	var asked []prompt.Request
	ask := func(_ context.Context, req prompt.Request) ([]byte, error) {
		asked = append(asked, req)
		return []byte("123456"), nil
	}
	env := func(kind string) func(string) string {
		return func(k string) string {
			if k == "SSH_ASKPASS_PROMPT" {
				return kind
			}
			return ""
		}
	}
	var out, errb bytes.Buffer
	if code := askpass(ask, env(""), "pi", []string{"(dietpi@pi) Verification code: "}, &out, &errb); code != 0 || out.String() != "123456\n" {
		t.Fatalf("exit %d out %q", code, out.String())
	}
	if len(asked) != 1 || asked[0].Host != "pi" || !strings.Contains(asked[0].Text, "Verification code:") ||
		!strings.Contains(asked[0].Title, "SSH login") {
		t.Fatalf("dialog %+v", asked)
	}
	for _, c := range []struct{ kind, text string }{
		{"", "Are you sure you want to continue connecting (yes/no/[fingerprint])?"},
		{"confirm", "Allow use of key?"},
	} {
		out.Reset()
		if code := askpass(ask, env(c.kind), "pi", []string{c.text}, &out, &errb); code != 1 || out.Len() != 0 {
			t.Fatalf("%q: exit %d out %q", c.text, code, out.String())
		}
	}
	if code := askpass(ask, env("none"), "pi", []string{"Confirm user presence"}, &out, &errb); code != 0 || len(asked) != 1 {
		t.Fatalf("notice: exit %d dialogs %d", code, len(asked))
	}
	cancel := func(context.Context, prompt.Request) ([]byte, error) { return nil, prompt.ErrCancelled }
	out.Reset()
	if code := askpass(cancel, env(""), "pi", []string{"Password:"}, &out, &errb); code != 1 || out.Len() != 0 {
		t.Fatalf("cancel: exit %d out %q", code, out.String())
	}
}

// The host shown in the SSH login dialog comes from the environment: one that
// psudo -H would refuse is refused here too, even with a live login's token.
func TestAskpassModeRefusesAnInvalidHost(t *testing.T) {
	dir := t.TempDir()
	token := strings.Repeat("0123456789abcdef", 4)
	if err := os.WriteFile(filepath.Join(dir, "askpass-"+token), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !askpassAllowed("web1", dir, token) {
		t.Fatal("a live login for a valid host is refused")
	}
	for _, host := range []string{"this computer", "web1\n\nEnter the password for this computer", "web\u202e1", ""} {
		if askpassAllowed(host, dir, token) {
			t.Errorf("host %q accepted", host)
		}
	}
	if askpassAllowed("web1", dir, strings.Repeat("a", 64)) {
		t.Error("a token with no login accepted")
	}
}

func TestAskpassModeRefusesWithoutALiveLogin(t *testing.T) {
	t.Setenv(runner.AskpassHostEnv, "evil")
	for _, tok := range []string{"", strings.Repeat("a", 64), "../../etc/passwd"} {
		t.Setenv(runner.AskpassTokenEnv, tok)
		var out, errb bytes.Buffer
		if code := run([]string{"Password:"}, nil, &out, &errb); code != 1 || out.Len() != 0 ||
			!strings.Contains(errb.String(), "did not start") {
			t.Fatalf("token %q: exit %d out %q err %q", tok, code, out.String(), errb.String())
		}
	}
}

func TestSecretUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"--secret"}, {"--secret", "NOEQUALS", "x"}, {"--secret", "PATH=a", "x"},
		{"--secret=X=Bad", "x"}, {"--secret", "X=a"}, {"--secret", "X=a", "--"}, {"-H", "a", "-H", "b", "--secret", "X=a", "x"},
		{"--secret-set=Bad Name"}, {"--secret-list=x"}, {"--secret-delete="}} {
		var out, errb bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%q: exit %d %s", args, code, errb.String())
		}
	}
}

type fakeUI struct {
	asked   []string
	answer  []byte
	choices []int
}

func (u *fakeUI) Ask(_ context.Context, r prompt.Request) ([]byte, error) {
	u.asked = append(u.asked, r.Text)
	if u.answer == nil {
		return nil, prompt.ErrCancelled
	}
	return append([]byte(nil), u.answer...), nil
}

func (u *fakeUI) Choose(_ context.Context, c prompt.Choice) (int, error) {
	u.asked = append(u.asked, c.Text)
	if len(u.choices) == 0 {
		return 0, nil
	}
	n := u.choices[0]
	u.choices = u.choices[1:]
	return n, nil
}

type mapVault map[string][]byte

func (m mapVault) Has(n string) (bool, error)   { _, ok := m[n]; return ok, nil }
func (m mapVault) Get(n string) ([]byte, error) { return m[n], nil }
func (m mapVault) Put(n string, v []byte) error { m[n] = append([]byte(nil), v...); return nil }
func (m mapVault) Delete(n string) error        { delete(m, n); return nil }
func (m mapVault) List() ([]string, error) {
	var out []string
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func TestSecretAdmin(t *testing.T) {
	v := mapVault{}
	ui := &fakeUI{}
	var out, errb bytes.Buffer
	cmd := func(stdin string) *secretCmd {
		out.Reset()
		errb.Reset()
		return &secretCmd{harness: "claude-code", vault: v, ui: ui, stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb,
			policy: func() (secrets.Policy, error) {
				return secrets.ParsePolicy([]byte(`{"secrets":{"gh":{"commands":["gh"],"ssh_hosts":["prod"]}}}`))
			}}
	}
	ui.answer = []byte("typed-value")
	if code := cmd("").run("secret-set", "gh"); code != 0 || string(v["gh"]) != "typed-value" || strings.Contains(out.String(), "add a rule") {
		t.Fatalf("set: %d %s %s", code, out.String(), errb.String())
	}
	// Replacing asks first; Cancel keeps the old value.
	if code := cmd("new\n").run("secret-import", "gh"); code != 251 || string(v["gh"]) != "typed-value" {
		t.Fatalf("replace cancelled: %d", code)
	}
	ui.choices = []int{1}
	if code := cmd("line1\nline2\n").run("secret-import", "gh"); code != 0 || string(v["gh"]) != "line1\nline2" {
		t.Fatalf("import: %d %q", code, v["gh"])
	}
	if code := cmd("").run("secret-import", "other"); code != 1 || v["other"] != nil {
		t.Fatalf("empty import: %d", code)
	}
	// A new secret from stdin is the caller's value, not the user's: it is
	// stored only after the user agrees.
	if code := cmd("x").run("secret-import", "other"); code != 251 || v["other"] != nil {
		t.Fatalf("import of a new secret without approval: %d %q", code, v["other"])
	}
	ui.choices = []int{1}
	if code := cmd("x").run("secret-import", "other"); code != 0 || !strings.Contains(out.String(), `"other": { "commands"`) {
		t.Fatalf("import without rule: %d %s", code, out.String())
	}
	ui.answer = nil
	if code := cmd("").run("secret-set", "third"); code != 251 || v["third"] != nil {
		t.Fatalf("set cancelled: %d", code)
	}
	if code := cmd("").run("secret-list", ""); code != 0 ||
		out.String() != "gh\tcommands: gh; hosts: this computer, prod\nother\t(no rule in config.json yet; psudo offers one on first use)\n" {
		t.Fatalf("list: %q", out.String())
	}
	// Secrets kept for the current session are listed and marked, and can be
	// deleted like the others.
	session := map[string]bool{"gh": true, "just-now": true}
	c := cmd("")
	c.sessionNames = func() ([]string, error) {
		var names []string
		for n := range session {
			names = append(names, n)
		}
		return names, nil
	}
	c.forget = func(name string) error { delete(session, name); return nil }
	if code := c.run("secret-list", ""); code != 0 || !strings.Contains(out.String(), "just-now\t(no rule in config.json yet; "+
		"psudo offers one on first use)\tthis session only\n") || strings.Contains(out.String(), "prod\tthis session") {
		t.Fatalf("list with a session: %q", out.String())
	}
	ui.choices = []int{1}
	if code := c.run("secret-delete", "just-now"); code != 0 || session["just-now"] || !session["gh"] {
		t.Fatalf("delete from the session: %d %v", code, session)
	}
	if strings.Contains(out.String(), "line1") || strings.Contains(errb.String(), "line1") {
		t.Fatal("value printed")
	}
	if code := cmd("").run("secret-delete", "gh"); code != 251 || v["gh"] == nil {
		t.Fatalf("delete cancelled: %d", code)
	}
	ui.choices = []int{1}
	if code := cmd("").run("secret-delete", "gh"); code != 0 || v["gh"] != nil {
		t.Fatalf("delete: %d", code)
	}
	if code := cmd("").run("secret-delete", "gh"); code != 1 {
		t.Fatalf("delete missing: %d", code)
	}
}
