package runner_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/prompt"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/runner"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
)

const secret = `test-only 'pass' \ $(x) "with" spaces`

// The test binary doubles as fake sudo and fake ssh (helper-process pattern).
func TestMain(m *testing.M) {
	switch os.Getenv("PSUDO_FAKE") {
	case "sudo":
		os.Exit(fakeSudo())
	case "ssh":
		os.Exit(fakeSSH())
	case "askpass":
		// Stands in for psudo's own askpass mode: it answers with what the
		// "user" typed, or cancels when nothing was typed.
		logCall("askpass.log")
		// The runner's one-time token file must exist while ssh asks.
		ctl := filepath.Join(filepath.Dir(os.Getenv("PSUDO_STATE")), "ctl")
		if d, err := os.ReadFile(filepath.Join(os.Getenv("PSUDO_STATE"), "ctl-dir")); err == nil {
			ctl = string(d)
		}
		if !runner.AskpassAuthorized(ctl, os.Getenv(runner.AskpassTokenEnv)) {
			os.Exit(3)
		}
		typed, err := os.ReadFile(filepath.Join(os.Getenv("PSUDO_STATE"), "otp-typed"))
		if err != nil {
			os.Exit(1)
		}
		fmt.Println(string(typed))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func logCall(name string) {
	f, err := os.OpenFile(filepath.Join(os.Getenv("PSUDO_STATE"), name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(map[string]any{"argv": os.Args[1:], "env": os.Environ()})
}

// fakeSudo emulates the parts of sudo psudo relies on. Like real sudo without
// a tty, its credential ticket is keyed by the parent process, and -v does
// not read stdin while a ticket is valid.
func fakeSudo() int {
	logCall("sudo.log")
	state := os.Getenv("PSUDO_STATE")
	args := os.Args[1:]
	mode := func(name string) bool { return exists(filepath.Join(state, name)) }
	ticket := filepath.Join(state, fmt.Sprintf("ticket-%d", os.Getppid()))
	cached := filepath.Join(state, "cached")
	// "nopasswd" models sudoers NOPASSWD: nothing reads stdin.
	// "noticket" models a target whose timestamp does not carry between
	// separate sudo invocations.
	valid := exists(ticket) || exists(cached) || mode("nopasswd")
	// authenticate reads one password line like sudo -S, with sudo's messages.
	authenticate := func() bool {
		if mode("nopasswd") {
			return true
		}
		if mode("requiretty") {
			fmt.Fprintln(os.Stderr, "sudo: a terminal is required to read the password")
			return false
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		want, _ := os.ReadFile(filepath.Join(state, "password"))
		if err != nil || strings.TrimSuffix(line, "\n") != string(want) {
			fmt.Fprintln(os.Stderr, "Sorry, try again.\nsudo: 1 incorrect password attempt")
			return false
		}
		if mode("denied") {
			fmt.Fprintln(os.Stderr, "Sorry, user test may not run sudo on host.")
			return false
		}
		return true
	}
	run := func(argv []string) int {
		path, err := exec.LookPath(argv[0])
		if err != nil {
			return 127
		}
		syscall.Exec(path, argv, os.Environ())
		return 126
	}
	switch {
	case reflect.DeepEqual(args, []string{"-k"}):
		os.Remove(ticket)
		os.Remove(cached)
		return 0
	case reflect.DeepEqual(args, []string{"-S", "-p", "", "-v"}):
		if valid {
			return 0
		}
		if !authenticate() {
			return 1
		}
		if !mode("noticket") {
			os.WriteFile(ticket, nil, 0o600)
		}
		return 0
	case reflect.DeepEqual(args, []string{"-n", "-v"}):
		if valid {
			return 0
		}
		return 1
	case len(args) >= 3 && args[0] == "-n" && args[1] == "--":
		// Real sudo -n reports a disallowed command this way, too.
		if !valid || mode("forbidcmd") {
			fmt.Fprintln(os.Stderr, "sudo: a password is required")
			return 1
		}
		return run(args[2:])
	case len(args) >= 7 && reflect.DeepEqual(args[:6], []string{"-k", "-S", "-p", "", "-l", "--"}):
		if !authenticate() {
			return 1
		}
		if mode("noshell") && args[6] == "/bin/sh" || mode("forbidcmd") && args[6] != "/bin/sh" {
			fmt.Fprintf(os.Stderr, "Sorry, user test is not allowed to execute '%s' as root on host.\n", args[6])
			return 1
		}
		return 0
	case len(args) >= 6 && reflect.DeepEqual(args[:5], []string{"-k", "-S", "-p", "", "--"}):
		if !authenticate() {
			return 1
		}
		if mode("noshell") && args[5] == "/bin/sh" {
			return 1
		}
		return run(args[5:])
	}
	fmt.Fprintf(os.Stderr, "fake sudo: unexpected arguments %q\n", args)
	return 99
}

// fakeSSH parses psudo's fixed options, then joins the remote words with
// spaces and hands them to /bin/sh, as OpenSSH and a POSIX login shell do.
func fakeSSH() int {
	logCall("ssh.log")
	args := os.Args[1:]
	opts := map[string]string{}
	control := ""
	i := 0
	for i < len(args) && args[i] != "--" {
		switch args[i] {
		case "-T":
			i++
		case "-o":
			k, v, _ := strings.Cut(args[i+1], "=")
			opts[k] = v
			i += 2
		case "-O":
			control = args[i+1]
			i += 2
		default:
			fmt.Fprintf(os.Stderr, "fake ssh: unexpected option %q\n", args[i])
			return 98
		}
	}
	if i+1 >= len(args) {
		return 97
	}
	host := args[i+1]
	// A shared connection is modelled as a file at ControlPath (%C = host).
	socket := strings.ReplaceAll(opts["ControlPath"], "%C", host)
	shared := socket != "" && exists(socket)
	if control == "check" {
		if shared {
			return 0
		}
		fmt.Fprintln(os.Stderr, "Control socket connect: No such file or directory")
		return 255
	}
	if i+2 > len(args) {
		return 97
	}
	rest := strings.Join(args[i+2:], " ")
	switch {
	case host == "unreachable":
		fmt.Fprintln(os.Stderr, "ssh: connect to host unreachable port 22: Connection refused")
		return 255
	case host == "otp" && opts["ControlMaster"] == "yes":
		// Interactive login: one-time code through SSH_ASKPASS.
		if opts["BatchMode"] == "yes" || os.Getenv("SSH_ASKPASS_REQUIRE") != "force" {
			return 255
		}
		out, err := exec.Command(os.Getenv("SSH_ASKPASS"), "(test@otp) Verification code:").Output()
		if err != nil || string(out) != "123456\n" {
			fmt.Fprintln(os.Stderr, "test@otp: Permission denied (keyboard-interactive).")
			return 255
		}
		os.WriteFile(socket, nil, 0o600)
	case host == "otp" && !shared:
		fmt.Fprintln(os.Stderr, "test@otp: Permission denied (keyboard-interactive).")
		return 255
	case host == "drops" && rest != "true":
		return 255
	case host == "banner" && rest != "true":
		fmt.Println("Welcome to banner")
	case host == "echoes" && rest != "true":
		// A forced command or an appliance shell: it ignores the command it
		// is given and echoes whatever arrives on stdin.
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			fmt.Println("unknown command: " + sc.Text())
		}
		return 0
	}
	cmd := exec.Command(testShell(), "-c", rest)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			return e.ExitCode()
		}
		return 96
	}
	return 0
}

type memStore struct {
	record *cache.Record
	calls  int
	writes int
}

func (m *memStore) Metadata() (*cache.Meta, error) { m.calls++; return m.record.Meta(), nil }
func (m *memStore) Load() (*cache.Record, error) {
	m.calls++
	if m.record == nil {
		return nil, nil
	}
	r := *m.record
	return &r, nil
}
func (m *memStore) Save(r cache.Record) error { m.calls++; m.writes++; m.record = &r; return nil }
func (m *memStore) Clear() error              { m.calls++; m.record = nil; return nil }

type fixture struct {
	t        *testing.T
	noticket bool
	state    string
	host     string
	r        *runner.Runner
	out, err bytes.Buffer
	asks     []prompt.Request
	answer   string
	askErr   error
}

func wrapper(t *testing.T, dir, name, kind, state string) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\nPSUDO_FAKE=%s PSUDO_STATE=%s exec %s \"$@\"\n",
		kind, shquote.Quote(state), shquote.Quote(exe))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func newFixture(t *testing.T, host string) *fixture {
	// A quote and space in the path exercise quoting of the sudo path itself.
	base := filepath.Join(t.TempDir(), "it's here")
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(state, "password"), []byte(secret), 0o600)
	sudo := wrapper(t, base, "fake-sudo", "sudo", state)
	f := &fixture{t: t, state: state, host: host, answer: secret}
	f.r = &runner.Runner{
		Title: "sudo password (test)", Shell: testShell(), LocalSudo: sudo, RemoteSudo: sudo,
		SSH:      wrapper(t, base, "fake-ssh", "ssh", state),
		LocalEnv: runner.LocalEnv(os.Environ()), SSHEnv: runner.SSHEnv(os.Environ()),
		Ask: func(_ context.Context, req prompt.Request) ([]byte, error) {
			f.asks = append(f.asks, req)
			if f.askErr != nil {
				return nil, f.askErr
			}
			return []byte(f.answer), nil
		},
		Lock:   func() (func(), error) { return func() {}, nil },
		TTL:    func() (int, error) { return 7200, nil },
		Now:    func() time.Time { return time.Unix(1000, 0) },
		Stdout: &f.out, Stderr: &f.err,
	}
	return f
}

func (f *fixture) run(argv ...string) int { return f.r.Run(context.Background(), f.host, argv) }

func (f *fixture) read(name string) string {
	data, _ := os.ReadFile(filepath.Join(f.state, name))
	return string(data)
}

func (f *fixture) assertNoLeak() {
	f.t.Helper()
	for name, text := range map[string]string{"stdout": f.out.String(), "stderr": f.err.String(),
		"sudo argv/env": f.read("sudo.log"), "ssh argv/env": f.read("ssh.log")} {
		if strings.Contains(text, secret) {
			f.t.Errorf("password leaked into %s", name)
		}
	}
	for _, req := range f.asks {
		if strings.Contains(req.Title+req.Host+req.Command, secret) {
			f.t.Error("password leaked into the dialog request")
		}
	}
}

// Both transports must pass the same suite (acceptance criterion 7), on
// targets that keep sudo's timestamp and on targets that do not.
func forEachTarget(t *testing.T, test func(t *testing.T, f *fixture)) {
	for name, host := range map[string]string{"local": "", "remote": "example-host"} {
		for _, noticket := range []bool{false, true} {
			label := name
			if noticket {
				label += "-noticket"
			}
			t.Run(label, func(t *testing.T) {
				f := newFixture(t, host)
				if noticket {
					f.noticket = true
					os.WriteFile(filepath.Join(f.state, "noticket"), nil, 0o600)
				}
				test(t, f)
			})
		}
	}
}

func TestArgumentVectorArrivesUnchanged(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		argv := []string{"printf", `[%s]\n`, "a b", "it's", `"q"`, "$(touch pwned)", "", ";", `back\slash`, "*", "x\ny"}
		if code := f.run(argv...); code != 0 {
			t.Fatalf("exit %d, stderr %q", code, f.err.String())
		}
		want := "[a b]\n[it's]\n[\"q\"]\n[$(touch pwned)]\n[]\n[;]\n[back\\slash]\n[*]\n[x\ny]\n"
		if f.out.String() != want {
			t.Fatalf("stdout %q, want %q", f.out.String(), want)
		}
		if len(f.asks) != 1 || f.asks[0].Host != f.host || f.asks[0].Command != shquote.Join(argv) {
			t.Fatalf("dialog request %+v", f.asks)
		}
		f.assertNoLeak()
	})
}

func TestCachedSudoCredentialNeverFeedsPasswordToCommand(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		os.WriteFile(filepath.Join(f.state, "cached"), nil, 0o600)
		if code := f.run("cat"); code != 0 {
			t.Fatalf("exit %d, stderr %q", code, f.err.String())
		}
		if f.out.Len() != 0 {
			t.Fatalf("command read stdin: %q", f.out.String())
		}
		f.assertNoLeak()
	})
}

// When sudo does not consume the password (NOPASSWD), it must still never
// reach the command: step 3 runs with stdin closed.
func TestUnreadPasswordNeverReachesCommand(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		os.WriteFile(filepath.Join(f.state, "nopasswd"), nil, 0o600)
		if code := f.run("cat"); code != 0 || f.out.Len() != 0 {
			t.Fatalf("exit %d stdout %q", code, f.out.String())
		}
	})
}

// Spec §6.3: invalidate, validate, execute, in that order.
func TestExecutionSequence(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		f.run("true")
		var steps [][]string
		for _, line := range strings.Split(strings.TrimSpace(f.read("sudo.log")), "\n") {
			var c struct{ Argv []string }
			json.Unmarshal([]byte(line), &c)
			steps = append(steps, c.Argv)
		}
		wrapped := []string{"/bin/sh", "-c", `exec "$@" </dev/null`, "psudo", "true"}
		allowed := []string{"-k", "-S", "-p", "", "-l", "--", "true"}
		want := [][]string{{"-k"}, {"-S", "-p", "", "-v"}, allowed, {"-n", "-v"}, {"-n", "--", "true"}, {"-k"}}
		if f.noticket {
			want = [][]string{{"-k"}, {"-S", "-p", "", "-v"}, allowed, {"-n", "-v"},
				append([]string{"-k", "-S", "-p", "", "-l", "--"}, wrapped...),
				append([]string{"-k", "-S", "-p", "", "--"}, wrapped...), {"-k"}}
		}
		if !reflect.DeepEqual(steps, want) {
			t.Fatalf("sudo calls %q, want %q", steps, want)
		}
	})
}

func TestCommandExitCodeAndStreams(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		code := f.run("sh", "-c", "echo out; echo err >&2; exit 7")
		if code != 7 || f.out.String() != "out\n" || !strings.Contains(f.err.String(), "err") {
			t.Fatalf("exit %d stdout %q stderr %q", code, f.out.String(), f.err.String())
		}
		if strings.Contains(f.err.String(), "psudo:") {
			t.Fatalf("psudo reported a failure for the command's own exit code: %q", f.err.String())
		}
	})
}

func TestWrongPasswordDoesNotRunOrRetry(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		sentinel := filepath.Join(f.state, "ran")
		f.answer = "wrong"
		if code := f.run("touch", sentinel); code != runner.ExitAuthFailed {
			t.Fatalf("exit %d, want 252", code)
		}
		if exists(sentinel) || len(f.asks) != 1 {
			t.Fatalf("ran=%v asks=%d", exists(sentinel), len(f.asks))
		}
		if !strings.Contains(f.err.String(), "psudo: WRONG PASSWORD:") || strings.Contains(f.err.String(), "Sorry") {
			t.Fatalf("stderr %q", f.err.String())
		}
	})
}

// Regression (compton): every sudoers entry is NOPASSWD, so -v succeeds
// without reading the password, but the command is not allowed. psudo must
// say NOT PERMITTED instead of passing through "a password is required"
// as the command's own exit 1.
func TestDisallowedCommandIsNotPermitted(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		for _, mode := range []string{"nopasswd", "forbidcmd"} {
			os.WriteFile(filepath.Join(f.state, mode), nil, 0o600)
		}
		sentinel := filepath.Join(f.state, "ran")
		if code := f.run("touch", sentinel); code != runner.ExitAuthFailed || exists(sentinel) {
			t.Fatalf("exit %d ran=%v stderr %q", code, exists(sentinel), f.err.String())
		}
		if !strings.Contains(f.err.String(), "psudo: NOT PERMITTED:") || strings.Contains(f.err.String(), "password is required") {
			t.Fatalf("stderr %q", f.err.String())
		}
	})
}

// A target that keeps no timestamp and forbids /bin/sh is reported, not run.
func TestNoTimestampAndNoShellIsExplicit(t *testing.T) {
	for _, host := range []string{"", "example-host"} {
		f := newFixture(t, host)
		for _, mode := range []string{"noticket", "noshell"} {
			os.WriteFile(filepath.Join(f.state, mode), nil, 0o600)
		}
		sentinel := filepath.Join(f.state, "ran")
		if code := f.run("touch", sentinel); code != runner.ExitAuthFailed || exists(sentinel) {
			t.Fatalf("exit %d ran=%v", code, exists(sentinel))
		}
		if !strings.Contains(f.err.String(), "psudo: AUTHENTICATION FAILED: the password was accepted") {
			t.Fatalf("stderr %q", f.err.String())
		}
	}
}

// Each authentication refusal gets its own explicit psudo message.
func TestAuthenticationRefusals(t *testing.T) {
	for mode, want := range map[string]string{
		"denied":     "psudo: NOT PERMITTED:",
		"requiretty": "psudo: AUTHENTICATION FAILED:",
	} {
		forEachTarget(t, func(t *testing.T, f *fixture) {
			os.WriteFile(filepath.Join(f.state, mode), nil, 0o600)
			sentinel := filepath.Join(f.state, "ran")
			if code := f.run("touch", sentinel); code != runner.ExitAuthFailed || exists(sentinel) {
				t.Fatalf("%s: exit %d ran=%v", mode, code, exists(sentinel))
			}
			if !strings.Contains(f.err.String(), want) || strings.Contains(f.err.String(), "WRONG PASSWORD") {
				t.Fatalf("%s: stderr %q", mode, f.err.String())
			}
			if mode == "requiretty" && !strings.Contains(f.err.String(), "a terminal is required") {
				t.Fatalf("sudo's own message was not passed through: %q", f.err.String())
			}
		})
	}
}

func TestDialogOutcomes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{{prompt.ErrCancelled, runner.ExitCancelled}, {prompt.ErrNoProvider, runner.ExitNoProvider}} {
		forEachTarget(t, func(t *testing.T, f *fixture) {
			f.askErr = tc.err
			if code := f.run("true"); code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
			if f.read("sudo.log") != "" {
				t.Fatal("sudo ran although no password was given")
			}
			if strings.Count(f.read("ssh.log"), "\n") > 1 {
				t.Fatal("ssh ran the command although no password was given")
			}
		})
	}
}

func TestUnreachableHostFailsBeforeDialog(t *testing.T) {
	f := newFixture(t, "unreachable")
	if code := f.run("true"); code != runner.ExitSSHFailed {
		t.Fatalf("exit %d, want 255", code)
	}
	if len(f.asks) != 0 || !strings.Contains(f.err.String(), "psudo: cannot reach unreachable") {
		t.Fatalf("asks=%d stderr=%q", len(f.asks), f.err.String())
	}
}

func TestDroppedConnectionIsTransportFailure(t *testing.T) {
	f := newFixture(t, "drops")
	if code := f.run("true"); code != runner.ExitSSHFailed {
		t.Fatalf("exit %d, want 255", code)
	}
}

// A target that does not run psudo's script must never receive the password:
// here it would echo it straight back into the output the model reads.
func TestPasswordIsNotSentToATargetThatDoesNotRunTheScript(t *testing.T) {
	f := newFixture(t, "echoes")
	f.r.ReadyTimeout = 300 * time.Millisecond
	code := f.run("id")
	if code != runner.ExitAuthFailed || !strings.Contains(f.err.String(), "the password was not sent") {
		t.Fatalf("exit %d stdout %q stderr %q", code, f.out.String(), f.err.String())
	}
	if len(f.asks) != 1 || strings.Contains(f.out.String(), "unknown command") {
		t.Fatalf("asks %d, stdout %q", len(f.asks), f.out.String())
	}
	f.assertNoLeak()
}

// Characters the user cannot see are shown as escapes in the dialog.
func TestDialogShowsHiddenCharacters(t *testing.T) {
	f := newFixture(t, "")
	f.run("echo", "safe\u202etxt.exe", "a\x1b[2Kb", "tab\there")
	if len(f.asks) != 1 || f.asks[0].Command != `echo 'safe\u{202E}txt.exe' 'a\u{001B}[2Kb' 'tab	here'` {
		t.Fatalf("dialog %+v", f.asks)
	}
}

func TestLoginBannerPassesThrough(t *testing.T) {
	f := newFixture(t, "banner")
	if code := f.run("echo", "hi"); code != 0 || f.out.String() != "Welcome to banner\nhi\n" {
		t.Fatalf("exit %d stdout %q", code, f.out.String())
	}
}

func TestSSHInvocation(t *testing.T) {
	f := newFixture(t, "example-host")
	f.run("true")
	var calls []struct{ Argv []string }
	for _, line := range strings.Split(strings.TrimSpace(f.read("ssh.log")), "\n") {
		var c struct{ Argv []string }
		json.Unmarshal([]byte(line), &c)
		calls = append(calls, c)
	}
	if len(calls) != 2 {
		t.Fatalf("ssh calls %d", len(calls))
	}
	for _, c := range calls {
		if !reflect.DeepEqual(c.Argv[:7], []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", "example-host"}) {
			t.Fatalf("ssh argv %q", c.Argv)
		}
	}
}

// interactive enables psudo's interactive SSH login with a fake askpass.
func (f *fixture) interactive(typed string) string {
	dir := filepath.Join(filepath.Dir(f.state), "ctl")
	os.Mkdir(dir, 0o700)
	f.r.ControlDir = func() (string, error) { return dir, nil }
	f.r.Askpass = wrapper(f.t, filepath.Dir(f.state), "fake-askpass", "askpass", f.state)
	if typed != "" {
		os.WriteFile(filepath.Join(f.state, "otp-typed"), []byte(typed), 0o600)
	}
	return dir
}

func (f *fixture) sshCalls() [][]string {
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSpace(f.read("ssh.log")), "\n") {
		var c struct{ Argv []string }
		json.Unmarshal([]byte(line), &c)
		calls = append(calls, c.Argv)
	}
	return calls
}

func TestInteractiveSSHLoginIsKeptAndReused(t *testing.T) {
	f := newFixture(t, "otp")
	f.interactive("123456")
	if code := f.run("echo", "hi"); code != 0 || f.out.String() != "hi\n" {
		t.Fatalf("exit %d stdout %q stderr %q", code, f.out.String(), f.err.String())
	}
	if !strings.Contains(f.err.String(), "psudo: logged in to otp over SSH") {
		t.Fatalf("stderr %q", f.err.String())
	}
	if n := strings.Count(f.read("askpass.log"), "\n"); n != 1 {
		t.Fatalf("askpass ran %d times, want 1", n)
	}
	var askEnv struct{ Argv, Env []string }
	json.Unmarshal([]byte(f.read("askpass.log")), &askEnv)
	if !reflect.DeepEqual(askEnv.Argv, []string{"(test@otp) Verification code:"}) ||
		!strings.Contains(strings.Join(askEnv.Env, "\n"), runner.AskpassHostEnv+"=otp") {
		t.Fatalf("askpass argv %q", askEnv.Argv)
	}
	// The run itself never carries askpass settings and stays in batch mode.
	calls := f.sshCalls()
	last := calls[len(calls)-1]
	if strings.Join(last[:3], " ") != "-T -o BatchMode=yes" || !strings.Contains(strings.Join(last, " "), "ControlMaster=no") {
		t.Fatalf("run argv %q", last)
	}
	// Later commands reuse the connection: no second login.
	f.out.Reset()
	if code := f.run("echo", "again"); code != 0 || f.out.String() != "again\n" {
		t.Fatalf("second run exit %d stdout %q", code, f.out.String())
	}
	if n := strings.Count(f.read("askpass.log"), "\n"); n != 1 {
		t.Fatalf("askpass ran %d times after reuse, want 1", n)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(f.state), "ctl", "askpass-*")); len(left) != 0 {
		t.Fatalf("one-time token files left behind: %q", left)
	}
	if len(f.asks) != 2 {
		t.Fatalf("sudo dialogs %d, want one per command", len(f.asks))
	}
	f.assertNoLeak()
}

func TestRejectedOrCancelledSSHLoginFailsBeforeSudoDialog(t *testing.T) {
	for name, typed := range map[string]string{"wrong code": "000000", "cancelled": ""} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "otp")
			f.interactive(typed)
			if code := f.run("touch", filepath.Join(f.state, "ran")); code != runner.ExitSSHFailed {
				t.Fatalf("exit %d, want 255", code)
			}
			if len(f.asks) != 0 || exists(filepath.Join(f.state, "ran")) {
				t.Fatal("sudo dialog shown or command ran after a failed SSH login")
			}
			if !strings.Contains(f.err.String(), "psudo: SSH FAILED: could not connect to or log in to otp") {
				t.Fatalf("stderr %q", f.err.String())
			}
		})
	}
}

func TestInteractiveLoginIsNotUsedForKeyHostsOrUnreachable(t *testing.T) {
	f := newFixture(t, "example-host")
	f.interactive("123456")
	if code := f.run("true"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	u := newFixture(t, "unreachable")
	u.interactive("123456")
	if code := u.run("true"); code != runner.ExitSSHFailed || len(u.asks) != 0 {
		t.Fatalf("exit %d asks %d", code, len(u.asks))
	}
	for _, fx := range []*fixture{f, u} {
		if fx.read("askpass.log") != "" {
			t.Fatal("askpass ran although no login prompt was needed")
		}
	}
	// A key host runs with the user's own ssh configuration.
	calls := f.sshCalls()
	if last := calls[len(calls)-1]; strings.Contains(strings.Join(last, " "), "ControlPath") {
		t.Fatalf("key host run argv %q", last)
	}
}

func TestWithoutInteractiveLoginOnlyKeysAreTried(t *testing.T) {
	f := newFixture(t, "otp")
	if code := f.run("true"); code != runner.ExitSSHFailed || len(f.asks) != 0 {
		t.Fatalf("exit %d asks %d", code, len(f.asks))
	}
	if !strings.Contains(f.err.String(), "psudo: cannot reach otp over SSH with key authentication") {
		t.Fatalf("stderr %q", f.err.String())
	}
}

func TestValidHost(t *testing.T) {
	for host, ok := range map[string]bool{"web1": true, "me@example.com": true, "ssh://h:22": true,
		"": false, "-oProxyCommand=x": false, "a b": false, "a\nb": false, "a\tb": false,
		// Invisible and direction-changing characters would mislead the dialog.
		"web1\u202egro.live": false, "web\u200b1": false, "web\u00a01": false, "a\x1b[2Kb": false} {
		if runner.ValidHost(host) != ok {
			t.Errorf("ValidHost(%q) != %v", host, ok)
		}
	}
}

func TestEnvironmentFiltering(t *testing.T) {
	env := []string{"PATH=/evil", "HOME=/h", "USER=other", "LOGNAME=other", "LD_PRELOAD=x", "DYLD_INSERT_LIBRARIES=y",
		"LC_ALL=C", "SSH_AUTH_SOCK=/s", "SSH_ASKPASS=/a", "BASH_ENV=/b"}
	local := strings.Join(runner.LocalEnv(env), " ")
	// HOME, USER and LOGNAME are the account's, never the caller's: sudo may
	// hand HOME on to the root command, which reads its dotfiles from there.
	want := "PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C HOME=" + cache.Home() +
		" USER=" + cache.Account() + " LOGNAME=" + cache.Account()
	if local != want || cache.Home() == "/h" {
		t.Fatalf("local env %q, want %q", local, want)
	}
	ssh := strings.Join(runner.SSHEnv(env), " ")
	if strings.Contains(ssh, "LD_") || strings.Contains(ssh, "DYLD_") || strings.Contains(ssh, "ASKPASS") ||
		!strings.Contains(ssh, "SSH_AUTH_SOCK=/s") {
		t.Fatalf("ssh env %q", ssh)
	}
}

func TestLocalPasswordCache(t *testing.T) {
	f := newFixture(t, "")
	store := &memStore{}
	f.r.Store = func() (cache.Store, error) { return store, nil }
	for i := 0; i < 2; i++ {
		if code := f.run("true"); code != 0 {
			t.Fatalf("run %d exit %d stderr %q", i, code, f.err.String())
		}
	}
	if len(f.asks) != 1 || store.writes != 1 || store.record.Password != secret || store.record.CreatedAt != 1000 ||
		store.record.TTLSeconds != 7200 {
		t.Fatalf("asks=%d writes=%d record=%+v", len(f.asks), store.writes, store.record)
	}
	// The deadline is fixed: at expiry the dialog returns and the entry is replaced.
	f.r.Now = func() time.Time { return time.Unix(8200, 0) }
	if code := f.run("true"); code != 0 || len(f.asks) != 2 || store.record.CreatedAt != 8200 {
		t.Fatalf("exit %d asks=%d record=%+v", code, len(f.asks), store.record)
	}
}

// An account without a password: OK on an empty field is an answer, which is
// sent to sudo, and cached like any other.
func TestEmptyPasswordIsSentAndCached(t *testing.T) {
	forEachTarget(t, func(t *testing.T, f *fixture) {
		os.WriteFile(filepath.Join(f.state, "password"), nil, 0o600)
		f.answer = ""
		if code := f.run("true"); code != 0 {
			t.Fatalf("exit %d stderr %q", code, f.err.String())
		}
	})
	f := newFixture(t, "")
	os.WriteFile(filepath.Join(f.state, "password"), nil, 0o600)
	f.answer = ""
	store := &memStore{}
	f.r.Store = func() (cache.Store, error) { return store, nil }
	for i := 0; i < 2; i++ {
		if code := f.run("true"); code != 0 {
			t.Fatalf("run %d exit %d stderr %q", i, code, f.err.String())
		}
	}
	if len(f.asks) != 1 || store.writes != 1 {
		t.Fatalf("asks=%d writes=%d", len(f.asks), store.writes)
	}
}

func TestCacheDisabledAlwaysPrompts(t *testing.T) {
	f := newFixture(t, "")
	store := &memStore{record: &cache.Record{Password: secret, CreatedAt: 999, TTLSeconds: 7200}}
	f.r.Store = func() (cache.Store, error) { return store, nil }
	f.r.TTL = func() (int, error) { return 0, nil }
	f.run("true")
	f.run("true")
	if len(f.asks) != 2 || store.writes != 0 || store.record != nil {
		t.Fatalf("asks=%d writes=%d record=%+v", len(f.asks), store.writes, store.record)
	}
}

func TestStaleCachedPasswordIsClearedWithoutRetry(t *testing.T) {
	f := newFixture(t, "")
	store := &memStore{record: &cache.Record{Password: "old", CreatedAt: 999, TTLSeconds: 7200}}
	f.r.Store = func() (cache.Store, error) { return store, nil }
	sentinel := filepath.Join(f.state, "ran")
	if code := f.run("touch", sentinel); code != runner.ExitAuthFailed {
		t.Fatalf("exit %d", code)
	}
	if len(f.asks) != 0 || store.record != nil || exists(sentinel) {
		t.Fatalf("asks=%d record=%+v ran=%v", len(f.asks), store.record, exists(sentinel))
	}
	if !strings.Contains(f.err.String(), "psudo: WRONG PASSWORD: the cached") {
		t.Fatalf("stderr %q", f.err.String())
	}
}

func TestInvalidConfigFailsClosed(t *testing.T) {
	f := newFixture(t, "")
	f.r.Store = func() (cache.Store, error) { return &memStore{}, nil }
	f.r.TTL = func() (int, error) { return 0, cache.ErrConfig }
	if code := f.run("true"); code != runner.ExitNoProvider || len(f.asks) != 0 || f.read("sudo.log") != "" {
		t.Fatalf("exit %d asks=%d", code, len(f.asks))
	}
}

func TestRemoteNeverTouchesCache(t *testing.T) {
	f := newFixture(t, "example-host")
	store := &memStore{record: &cache.Record{Password: secret, CreatedAt: 999, TTLSeconds: 7200}}
	f.r.Store = func() (cache.Store, error) { return store, nil }
	f.run("true")
	f.run("true")
	if store.calls != 0 || len(f.asks) != 2 {
		t.Fatalf("store calls=%d asks=%d", store.calls, len(f.asks))
	}
}

// testShell lets the suite run under another POSIX shell, e.g. dash (Debian's /bin/sh):
//
//	PSUDO_TEST_SHELL=/bin/dash go test ./internal/runner
func testShell() string {
	if sh := os.Getenv("PSUDO_TEST_SHELL"); sh != "" {
		return sh
	}
	return "/bin/sh"
}

// TestRealOpenSSHInteractiveLogin runs the interactive login against a real
// sshd. It is opt-in: PSUDO_SSHLAB_CONFIG names an ssh_config with a host
// "lab" whose key has the passphrase in PSUDO_SSHLAB_PASSPHRASE, so key
// authentication alone (BatchMode) fails, as it does for a TOTP host.
func TestRealOpenSSHInteractiveLogin(t *testing.T) {
	cfg := os.Getenv("PSUDO_SSHLAB_CONFIG")
	if cfg == "" {
		t.Skip("set PSUDO_SSHLAB_CONFIG to run against a real sshd")
	}
	f := newFixture(t, "lab")
	base := filepath.Dir(f.state)
	sshWrap := filepath.Join(base, "real-ssh")
	os.WriteFile(sshWrap, []byte("#!/bin/sh\nexec /usr/bin/ssh -F "+shquote.Quote(cfg)+" \"$@\"\n"), 0o700)
	f.r.SSH = sshWrap
	f.interactive(os.Getenv("PSUDO_SSHLAB_PASSPHRASE"))
	ctl := fmt.Sprintf("/tmp/psudo-lab-%d", os.Getpid())
	os.Mkdir(ctl, 0o700)
	os.WriteFile(filepath.Join(f.state, "ctl-dir"), []byte(ctl), 0o600)
	defer os.RemoveAll(ctl)
	f.r.ControlDir = func() (string, error) { return ctl, nil }
	f.r.Persist = time.Minute
	defer runner.CloseShared("/usr/bin/ssh", ctl)

	start := time.Now()
	if code := f.run("echo", "first"); code != 0 || f.out.String() != "first\n" {
		t.Fatalf("exit %d stdout %q stderr %q", code, f.out.String(), f.err.String())
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("login held the call open for %v", d)
	}
	f.out.Reset()
	if code := f.run("echo", "second"); code != 0 || f.out.String() != "second\n" {
		t.Fatalf("reuse exit %d stdout %q stderr %q", code, f.out.String(), f.err.String())
	}
	if n := strings.Count(f.read("askpass.log"), "\n"); n != 1 {
		t.Fatalf("askpass ran %d times, want 1 (the second command must reuse the connection)", n)
	}
	if n, err := runner.CloseShared("/usr/bin/ssh", ctl); err != nil || n != 1 {
		t.Fatalf("CloseShared closed %d, %v", n, err)
	}
	f.assertNoLeak()
}
