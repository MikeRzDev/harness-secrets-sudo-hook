// Package runner executes a privileged command locally or over SSH. Both
// transports run the same fixed script (spec §6.3): invalidate any cached
// sudo credential, validate the password read from stdin, then execute the
// command non-interactively with stdin closed.
package runner

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/prompt"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
)

// Exit codes from spec §6.1.
const (
	ExitUsage      = 2
	ExitNoProvider = 250
	ExitCancelled  = 251
	ExitAuthFailed = 252
	ExitSSHFailed  = 255
)

// Script is fixed text: the sudo path, the marker and the command arrive as
// positional parameters, never interpolated. It is a single line so it also
// survives login shells that dislike newlines inside quotes.
//
// The script first reports "<marker> ready". psudo sends the password only
// after that line, so the password never goes to a target that is not running
// this script: a forced command, a login shell that is not a POSIX shell or a
// startup file that reads stdin gets no input, and cannot echo the password
// back into the output.
//
// The password is the first line of stdin. It is read into a shell variable
// (never exported, never in any process's argv) and stdin is then closed for
// everything that follows, so the command can never read it. Each sudo that
// needs it receives it through a pipe from the printf builtin.
//
// Steps (spec §6.3): invalidate (-k), validate (-S -v), then execute. Before
// the command runs, the script reports one status line "<marker> <status>"
// on stdout: ok, badpw (wrong password), denied (not in sudoers / not
// allowed), authfail (any other sudo refusal) or nosudo.
//
// After validation, sudo -l checks that sudoers allows this exact command, so a
// refused command is reported as denied instead of surfacing as the
// command's own exit 1 ("a password is required" from sudo -n). That
// happens when every sudoers entry is NOPASSWD: -v then succeeds without
// reading the password, but other commands are still not allowed.
//
// Execution uses the timestamp created by -v when the target keeps one
// (sudo -n -v succeeds), so the exact command is what sudo authorizes and
// logs. Some targets do not carry that timestamp between separate sudo
// invocations; there the command is authenticated inline with -k -S and run
// through /bin/sh only to close its stdin. That needs sudoers to allow
// /bin/sh, which is checked (sudo -l) before anything runs; if it is not
// allowed the status is noshell.
const Script = `s=$1; m=$2; shift 2; ` +
	`if [ -z "$s" ]; then for c in /usr/bin/sudo /bin/sudo /usr/local/bin/sudo /run/wrappers/bin/sudo /run/current-system/sw/bin/sudo; do if [ -x "$c" ]; then s=$c; break; fi; done; fi; ` +
	`if [ -z "$s" ]; then echo 'psudo: sudo not found on target' >&2; printf '%s nosudo\n' "$m"; exit 1; fi; ` +
	`printf '%s ready\n' "$m"; IFS= read -r p || p=; exec </dev/null; ` +
	`"$s" -k; ` +
	`f=$(mktemp 2>/dev/null) || f=/dev/null; ` +
	`if printf '%s\n' "$p" | LC_ALL=C "$s" -S -p '' -v 2>"$f"; then t=ok; else ` +
	`e=$(cat "$f" 2>/dev/null); ` +
	`case $e in *"incorrect password"*|*"Sorry, try again"*) t=badpw;; *"sudoers"*|*"may not run"*|*"not allowed"*) t=denied;; *) t=authfail;; esac; ` +
	`[ "$t" = badpw ] || [ -z "$e" ] || printf '%s\n' "$e" >&2; fi; ` +
	`[ "$f" = /dev/null ] || rm -f "$f"; ` +
	`x=; if [ "$t" = ok ] && ! printf '%s\n' "$p" | "$s" -k -S -p '' -l -- "$@" >/dev/null 2>&1; then t=denied; fi; ` +
	`if [ "$t" = ok ]; then if "$s" -n -v 2>/dev/null; then x=ticket; ` +
	`elif printf '%s\n' "$p" | "$s" -k -S -p '' -l -- /bin/sh -c 'exec "$@" </dev/null' psudo "$@" >/dev/null 2>&1; then x=inline; ` +
	`else t=noshell; fi; fi; ` +
	`printf '%s %s\n' "$m" "$t"; ` +
	`if [ "$t" != ok ]; then p=; exit 1; fi; ` +
	`if [ "$x" = ticket ]; then p=; "$s" -n -- "$@"; rc=$?; ` +
	`else printf '%s\n' "$p" | "$s" -k -S -p '' -- /bin/sh -c 'exec "$@" </dev/null' psudo "$@"; rc=$?; p=; fi; ` +
	`"$s" -k; exit "$rc"`

// StatusReady is the first line both remote scripts report: the script is
// running and is about to read stdin.
const StatusReady = "ready"

// DefaultReadyWait bounds the wait for StatusReady: the time the target needs
// to start the script, after the connection itself is up.
const DefaultReadyWait = 30 * time.Second

// Status values reported by Script before the command runs.
const (
	statusOK       = "ok"
	statusBadPW    = "badpw"
	statusDenied   = "denied"
	statusAuthFail = "authfail"
	statusNoSudo   = "nosudo"
	statusNoShell  = "noshell"
)

// maxPreamble bounds output (such as login banners) accepted before the marker.
const maxPreamble = 64 << 10

// Runner holds every external dependency so tests can substitute fakes.
type Runner struct {
	Title      string
	Shell      string // local shell, "/bin/sh"
	LocalSudo  string // "/usr/bin/sudo"
	RemoteSudo string // "" lets the target resolve sudo from a fixed list
	SSH        string // absolute path to ssh
	LocalEnv   []string
	SSHEnv     []string
	Ask        prompt.Asker

	// Interactive SSH login (see connect). A nil ControlDir or an empty
	// Askpass means key authentication only.
	ControlDir func() (string, error)
	Askpass    string        // the askpass program: psudo itself
	Persist    time.Duration // 0 means DefaultPersist
	// ReadyTimeout is how long to wait for the script to report that it is
	// running before giving up without sending anything. 0 means DefaultReadyWait.
	ReadyTimeout time.Duration

	// Password cache for local targets. A nil Store disables caching.
	Store func() (cache.Store, error)
	TTL   func() (int, error)
	Lock  func() (func(), error)
	Now   func() time.Time

	Stdout, Stderr io.Writer
	Signals        <-chan os.Signal
}

// ValidHost rejects destinations that ssh could parse as options or that
// would be ambiguous in the dialog: whitespace, control characters, and
// characters that are invisible or change the direction of the text.
func ValidHost(host string) bool {
	if host == "" || strings.HasPrefix(host, "-") {
		return false
	}
	for _, r := range host {
		if unicode.IsSpace(r) || r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ReadyWait is the effective ReadyTimeout.
func (r *Runner) ReadyWait() time.Duration {
	if r.ReadyTimeout > 0 {
		return r.ReadyTimeout
	}
	return DefaultReadyWait
}

// RemoteCommand builds the string ssh hands to the remote login shell.
func RemoteCommand(sudo, marker string, argv []string) string {
	return "exec /bin/sh -c " + shquote.Quote(Script) + " psudo " +
		shquote.Join(append([]string{sudo, marker}, argv...))
}

// SSHArgs are the options used for every connection that carries the sudo
// password. BatchMode means ssh can never fall back to prompting; extra
// options (psudo's shared connection) go before the host.
func SSHArgs(host string, command string, extra ...string) []string {
	args := append([]string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"}, extra...)
	return append(args, "--", host, command)
}

// NewMarker returns a random status-line marker.
func NewMarker() string { return newMarker() }

func newMarker() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "psudo-validated-" + hex.EncodeToString(b)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (r *Runner) fail(format string, args ...any) {
	fmt.Fprintf(r.Stderr, "psudo: "+format+"\n", args...)
}

func exitCode(state *os.ProcessState) int {
	if st, ok := state.Sys().(syscall.WaitStatus); ok && st.Signaled() {
		return 128 + int(st.Signal())
	}
	return state.ExitCode()
}

// Run executes argv as root on host ("" for the local machine) and returns
// the process exit code.
func (r *Runner) Run(ctx context.Context, host string, argv []string) int {
	remote := host != ""
	target := "this computer"
	if remote {
		target = host
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var proc *os.Process
	done := make(chan struct{})
	defer close(done)
	if r.Signals != nil {
		go func() {
			for {
				select {
				case sig := <-r.Signals:
					mu.Lock()
					if proc != nil {
						proc.Signal(sig)
					} else {
						cancel()
					}
					mu.Unlock()
				case <-done:
					return
				}
			}
		}()
	}

	var sshOpts []string
	if remote {
		if r.SSH == "" {
			r.fail("ssh is not installed")
			return ExitSSHFailed
		}
		opts, ok := r.connect(ctx, host)
		if !ok {
			return ExitSSHFailed
		}
		sshOpts = opts
	}

	release := func() {}
	var store cache.Store
	ttl := 0
	var password []byte
	fromCache := false
	if !remote && r.Store != nil {
		unlock, err := r.Lock()
		if err != nil {
			r.fail("could not lock the password cache")
			return ExitNoProvider
		}
		release = sync.OnceFunc(unlock)
		defer release()
		if ttl, err = r.TTL(); err != nil {
			r.fail("invalid cache settings in harness-root-hook config.json")
			return ExitNoProvider
		}
		if store, err = r.Store(); err != nil {
			r.fail("the OS credential store is unavailable")
			return ExitNoProvider
		}
		now := float64(r.Now().UnixNano()) / 1e9
		meta, err := store.Metadata()
		if err != nil {
			r.fail("could not read the OS credential store")
			return ExitNoProvider
		}
		if cache.Fresh(meta, ttl, now) {
			rec, err := store.Load()
			if err != nil {
				r.fail("could not read the OS credential store")
				return ExitNoProvider
			}
			// An empty password is a real one (an account without a password).
			if rec != nil && cache.Fresh(rec.Meta(), ttl, now) {
				password, fromCache = []byte(rec.Password), true
			}
		}
		if !fromCache {
			if err := store.Clear(); err != nil {
				r.fail("could not clear the expired password cache entry")
				return ExitNoProvider
			}
		}
	}

	if !fromCache {
		pw, err := r.Ask(ctx, prompt.Request{Title: r.Title, Host: host, Command: shquote.Visible(shquote.Join(argv)),
			Timeout: prompt.DefaultTimeout})
		switch {
		case errors.Is(err, prompt.ErrNoProvider):
			r.fail("no password dialog is available (a logged-in desktop session is required)")
			return ExitNoProvider
		case err != nil:
			r.fail("password dialog was cancelled or timed out; the command was not run")
			return ExitCancelled
		}
		password = pw
	}
	defer zero(password)
	if ctx.Err() != nil {
		r.fail("interrupted; the command was not run")
		return ExitCancelled
	}

	marker := newMarker()
	var cmd *exec.Cmd
	if remote {
		cmd = exec.Command(r.SSH, SSHArgs(host, RemoteCommand(r.RemoteSudo, marker, argv), sshOpts...)...)
		cmd.Env = r.SSHEnv
	} else {
		cmd = exec.Command(r.Shell, append([]string{"-c", Script, "psudo", r.LocalSudo, marker}, argv...)...)
		cmd.Env = r.LocalEnv
	}
	cmd.Stderr = r.Stderr
	stdin, err1 := cmd.StdinPipe()
	stdout, err2 := cmd.StdoutPipe()
	if err1 != nil || err2 != nil {
		r.fail("could not create pipes")
		return ExitAuthFailed
	}
	mu.Lock()
	err := cmd.Start()
	if err == nil {
		proc = cmd.Process
	}
	mu.Unlock()
	if err != nil {
		r.fail("could not start the %s transport", map[bool]string{true: "SSH", false: "local"}[remote])
		if remote {
			return ExitSSHFailed
		}
		return ExitAuthFailed
	}

	// The password is sent only after the script reports that it is the one
	// reading stdin. Until then nothing is written, so whatever else runs on
	// the target first cannot receive the password or print it.
	reader := bufio.NewReader(stdout)
	timer := time.AfterFunc(r.ReadyWait(), func() { cmd.Process.Kill() })
	status, overflow := r.awaitStatus(reader, marker)
	timer.Stop()
	sent := status == StatusReady && !overflow
	if sent {
		// The password goes only to the pipe; a write error means the child
		// already exited, which the marker check below reports.
		stdin.Write(password)
		stdin.Write([]byte{'\n'})
	}
	stdin.Close()
	if sent {
		status, overflow = r.awaitStatus(reader, marker)
	} else if status == StatusReady {
		status = ""
	}
	if overflow || (!sent && status == "") {
		cmd.Process.Kill()
	}
	validated := sent && status == statusOK
	if validated {
		if !fromCache && store != nil && ttl > 0 {
			rec := cache.Record{Password: string(password), CreatedAt: float64(r.Now().UnixNano()) / 1e9, TTLSeconds: ttl}
			if err := store.Save(rec); err != nil {
				r.fail("warning: could not cache the password; the command is running anyway")
			}
		}
		zero(password)
		release()
	}
	io.Copy(r.Stdout, reader)
	cmd.Wait()
	code := exitCode(cmd.ProcessState)
	if validated {
		return code
	}
	switch {
	case status == statusBadPW && fromCache:
		if store.Clear() == nil {
			r.fail("WRONG PASSWORD: the cached sudo password for %s was rejected and has been cleared. The command was not run; run it again to enter the password.", target)
		} else {
			r.fail("WRONG PASSWORD: the cached sudo password for %s was rejected and could not be cleared. The command was not run.", target)
		}
	case status == statusBadPW:
		r.fail("WRONG PASSWORD: sudo on %s rejected the password. The command was not run.", target)
	case status == statusDenied:
		r.fail("NOT PERMITTED: sudoers on %s does not allow this account to run that command (the password was not the problem). "+
			"The command was not run. Fix on the target: add a sudoers rule for this exact command.", target)
	case status == statusNoShell:
		r.fail("AUTHENTICATION FAILED: the password was accepted, but %s does not keep sudo's credential between commands "+
			"and its sudoers does not allow /bin/sh, which psudo needs there. The command was not run. "+
			"Fix on the target: allow the account to run /bin/sh via sudo, or set timestamp_timeout above 0.", target)
	case status == statusNoSudo:
		r.fail("AUTHENTICATION FAILED: sudo is not installed on %s. The command was not run.", target)
	case status == statusAuthFail:
		r.fail("AUTHENTICATION FAILED: sudo on %s refused to authenticate (see its message above). The command was not run.", target)
	case remote && (code == ExitSSHFailed || overflow):
		r.fail("SSH FAILED: the connection to %s failed or returned unexpected output. The command was not run.", host)
		return ExitSSHFailed
	case overflow:
		r.fail("AUTHENTICATION FAILED: unexpected output before authentication completed. The command was not run.")
	case !sent:
		r.fail("AUTHENTICATION FAILED: %s did not start psudo's script, so the password was not sent. Its login shell must be "+
			"POSIX-compatible and must run the command it is given. The command was not run.", target)
	default:
		r.fail("AUTHENTICATION FAILED: %s did not report an authentication result (exit %d). The command was not run.", target, code)
	}
	return ExitAuthFailed
}

// awaitStatus forwards output that precedes the status line and returns the
// status Script reported, or "" when none arrived.
func (r *Runner) awaitStatus(reader *bufio.Reader, marker string) (status string, overflow bool) {
	return AwaitStatus(reader, marker, r.Stdout)
}

// AwaitStatus copies output to w until a line "<marker> <status>", and
// returns that status, or "" when none arrived. overflow means more than
// 64 KiB came first.
func AwaitStatus(reader *bufio.Reader, marker string, w io.Writer) (status string, overflow bool) {
	prefix := marker + " "
	total, lineStart := 0, true
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			line := string(chunk)
			if lineStart && strings.HasPrefix(line, prefix) && strings.HasSuffix(line, "\n") {
				return strings.TrimSuffix(strings.TrimPrefix(line, prefix), "\n"), false
			}
			w.Write(chunk)
			total += len(chunk)
			lineStart = chunk[len(chunk)-1] == '\n'
			if total > maxPreamble {
				return "", true
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", false
		}
	}
}

var localKeep = []string{"TERM", "LANG", "TZ"}

// LocalEnv is a minimal environment for the local shell. PATH is fixed so a
// caller cannot substitute a program for the one receiving the password.
// HOME, USER and LOGNAME come from the account database, not from the caller:
// where sudo keeps HOME (as on macOS), the root command would otherwise read
// its dotfiles from a folder the caller chose, which the dialog does not show.
func LocalEnv(environ []string) []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "LC_") {
			env = append(env, kv)
			continue
		}
		for _, keep := range localKeep {
			if name == keep {
				env = append(env, kv)
			}
		}
	}
	return cache.Identity(env)
}

// SSHEnv keeps the user's environment (agent socket, config lookups) but
// drops variables that could inject code into ssh or make it prompt.
func SSHEnv(environ []string) []string {
	var env []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") ||
			strings.HasPrefix(name, "SSH_ASKPASS") {
			continue
		}
		env = append(env, kv)
	}
	// HOME, USER and LOGNAME are the account's own here as well: what ssh
	// starts (a ProxyCommand, psudo as its askpass program) must not work
	// from a home folder the caller chose.
	return cache.Identity(env)
}
