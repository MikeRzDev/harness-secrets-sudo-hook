// Package prompt shows a native password dialog on the harness machine. The
// host and command are always passed to the dialog program as separate
// arguments (data), never spliced into script source.
package prompt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/sysbin"
)

var (
	// ErrNoProvider means no dialog can be shown here (for example, no display).
	ErrNoProvider = errors.New("no password dialog is available")
	// ErrCancelled means the user cancelled, the dialog timed out, or the input
	// was unusable. An empty field confirmed with OK is an answer, not a cancel.
	ErrCancelled = errors.New("password dialog cancelled or timed out")
)

// DefaultTimeout is shorter than Claude Code's default 120 s Bash timeout.
const DefaultTimeout = 90 * time.Second

// Request describes what the user is asked to authorize.
type Request struct {
	Title   string
	Host    string // empty means the local machine
	Command string // already rendered for display
	Text    string // when set, the whole dialog body instead of the sudo message
	Timeout time.Duration
}

func (req Request) message() string {
	if req.Text != "" {
		return req.Text
	}
	return Message(req.Host, req.Command)
}

// LoginMessage is the dialog body for one of ssh's own login prompts (a
// password, a one-time code, a key passphrase), shown while psudo logs in.
//
// The prompt text comes from the SSH server, so characters that are invisible
// or reorder the text are shown as escapes.
func LoginMessage(host, sshPrompt string) string {
	return "Host: " + host + "\n\nSSH login asks:\n" + shquote.Visible(strings.TrimSpace(sshPrompt)) +
		"\n\nThis answer goes only to ssh, to log in to " + host +
		". psudo asks for the sudo password separately."
}

// Asker returns the password or ErrNoProvider / ErrCancelled. Alternative
// providers (for example a phone approval) implement the same signature.
type Asker func(ctx context.Context, req Request) ([]byte, error)

// Message is the dialog body.
func Message(host, command string) string {
	label := host
	if label == "" {
		label = "this computer"
	}
	return "Host: " + label + "\n\nCommand:\n" + command + "\n\nEnter your sudo password on " + label + " to run this command."
}

// Env abstracts the environment so dialog selection is testable.
type Env struct {
	GOOS   string
	Getenv func(string) string
	Find   func(string) string
	// App is psudo.app's executable on macOS, or "" when it is not installed.
	App string
	// Run executes a dialog program with stdin and returns stdout and the exit
	// code. A non-nil error means the program could not be started.
	Run func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, int, error)
}

// System is the production environment.
func System() Env {
	e := Env{GOOS: runtime.GOOS, Getenv: os.Getenv, Find: sysbin.Find, Run: runDialog}
	if TestApp && e.GOOS == "darwin" && appIsThisBuild() {
		e.App = AppExecutable
	}
	return e
}

// AppBundle is the test app (psudo --install=test-app). It shows psudo's
// dialogs on macOS as an app of its own, so tools that work with apps
// (computer use) can answer them during a regression run. Without it, the
// default, the dialogs come from osascript.
const AppBundle = "/Applications/psudo.app"

// appIsThisBuild reports whether the test app holds the same build as the
// running test build: the same Go build ID (the ad hoc signature makes the
// bytes differ). It keeps a stale copy from answering after a rebuild. It is
// no defence against a crafted binary, which can carry any build ID; that is
// why only a test build (TestApp) looks at the app at all.
var appIsThisBuild = sync.OnceValue(func() bool {
	self, err := os.Executable()
	return err == nil && sameBuild(self, AppExecutable)
})

// sameBuild reports whether app is an executable file with the Go build ID
// of self.
func sameBuild(self, app string) bool {
	info, err := os.Stat(app)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return false
	}
	mine, err := goBuildID(self)
	if err != nil {
		return false
	}
	id, err := goBuildID(app)
	return err == nil && id == mine
}

// goBuildID reads the Go build ID from the start of a binary, where the Go
// linker puts it (go tool buildid reads it the same way).
func goBuildID(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 32<<10)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	const start, end = "\xff Go build ID: \"", "\"\n \xff"
	i := bytes.Index(head, []byte(start))
	if i < 0 {
		return "", errors.New("no Go build ID")
	}
	rest := head[i+len(start):]
	j := bytes.Index(rest, []byte(end))
	if j <= 0 {
		return "", errors.New("no Go build ID")
	}
	return string(rest[:j]), nil
}

// AppExecutable is the psudo binary inside AppBundle.
const AppExecutable = AppBundle + "/Contents/MacOS/psudo"

func runDialog(ctx context.Context, name string, args []string, stdin []byte) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// The dialog program gets the account's own HOME, not the caller's.
	cmd.Env = cache.HelperEnv(os.Environ())
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// osascript reports a click on the cancel button as error -128. Any
		// other error means no dialog was shown, which must not read as a
		// refusal by the user.
		if name == osascript && ctx.Err() == nil && !strings.Contains(errOut.String(), "(-128)") {
			return nil, -1, fmt.Errorf("osascript: %s", strings.TrimSpace(errOut.String()))
		}
		return out.Bytes(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return nil, -1, err
	}
	return out.Bytes(), 0, nil
}

// show draws d with the first backend that can, and returns its Result.
func (e Env) show(ctx context.Context, d Dialog) (Result, error) {
	if err := d.check(); err != nil {
		return Result{}, err
	}
	bs, err := e.backends(d)
	if err != nil {
		return Result{}, err
	}
	// Hard stop slightly after the dialog's own timeout; expiry is a timeout.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.Seconds)*time.Second+5*time.Second)
	defer cancel()
	for _, b := range bs {
		out, code, err := e.Run(ctx, b.name, b.args, b.stdin)
		if ctx.Err() != nil {
			return Result{Outcome: TimedOut}, nil
		}
		if err != nil {
			continue // not started: the next backend may show it
		}
		if r := b.parse(out, code); r.Outcome != Unavailable {
			return r, nil
		}
	}
	return Result{Outcome: Unavailable}, nil
}

// Ask shows the dialog and returns the password.
func (e Env) Ask(ctx context.Context, req Request) ([]byte, error) {
	r, err := e.show(ctx, req.dialog())
	if err != nil {
		return nil, err
	}
	return r.answer()
}

// Choice is a request for one of up to three buttons. Buttons[0] is the
// refusal: it is the default button, so Return chooses it, and so do a
// timeout and a dialog that is closed. kdialog is the exception: it has no
// option to pick the default button, so there Return may press an approval.
type Choice struct {
	Title   string
	Text    string
	Buttons []string // 2 or 3 labels
	Timeout time.Duration
}

// Chooser returns the index of the button pressed. Refusal (index 0), a
// timeout and a closed dialog all return 0 with a nil error.
type Chooser func(ctx context.Context, c Choice) (int, error)

// Choose shows the dialog and returns the button index.
func (e Env) Choose(ctx context.Context, c Choice) (int, error) {
	d := c.dialog()
	r, err := e.show(ctx, d)
	if err != nil {
		return 0, err
	}
	return r.choice(d)
}
