// Package prompt shows a native password dialog on the harness machine. The
// host and command are always passed to the dialog program as separate
// arguments (data), never spliced into script source.
package prompt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
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

// macScript is fixed. Title, message and timeout arrive as argv items.
const macScript = `on run argv
activate
set r to display dialog (item 2 of argv) with title (item 1 of argv) default answer "" with hidden answer with icon caution giving up after ((item 3 of argv) as integer)
if gave up of r then error number -128
return text returned of r
end run`

// Env abstracts the environment so dialog selection is testable.
type Env struct {
	GOOS   string
	Getenv func(string) string
	Find   func(string) string
	// Run executes the dialog and returns stdout and the exit code. A non-nil
	// error means the program could not be started.
	Run func(ctx context.Context, name string, args []string) ([]byte, int, error)
}

// System is the production environment.
func System() Env {
	return Env{GOOS: runtime.GOOS, Getenv: os.Getenv, Find: sysbin.Find, Run: runDialog}
}

func runDialog(ctx context.Context, name string, args []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// The dialog program gets the account's own HOME, not the caller's.
	cmd.Env = cache.HelperEnv(os.Environ())
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// osascript reports a click on the cancel button as error -128. Any
		// other error means no dialog was shown, which must not read as a
		// refusal by the user.
		if name == "/usr/bin/osascript" && ctx.Err() == nil && !strings.Contains(errOut.String(), "(-128)") {
			return nil, -1, fmt.Errorf("osascript: %s", strings.TrimSpace(errOut.String()))
		}
		return out.Bytes(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return nil, -1, err
	}
	return out.Bytes(), 0, nil
}

// pangoEscape escapes text for GTK markup labels (zenity --text).
func pangoEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// Command picks the dialog program and its argument vector.
func (e Env) Command(req Request) (string, []string, error) {
	msg := req.message()
	seconds := int(req.Timeout / time.Second)
	if seconds <= 0 {
		seconds = int(DefaultTimeout / time.Second)
	}
	switch e.GOOS {
	case "darwin":
		return "/usr/bin/osascript", []string{"-e", macScript, req.Title, msg, strconv.Itoa(seconds)}, nil
	case "linux":
		display, wayland := e.Getenv("DISPLAY"), e.Getenv("WAYLAND_DISPLAY")
		if display == "" && wayland == "" {
			return "", nil, ErrNoProvider
		}
		if p := e.Find("zenity"); p != "" {
			return p, []string{"--entry", "--hide-text", "--title=" + req.Title,
				"--text=" + pangoEscape(msg), "--timeout=" + strconv.Itoa(seconds)}, nil
		}
		if p := e.Find("kdialog"); p != "" {
			// <qt><pre> forces rich text, so escaped content renders verbatim.
			return p, []string{"--title", req.Title, "--password",
				"<qt><pre>" + html.EscapeString(msg) + "</pre></qt>"}, nil
		}
		if p := e.Find("ssh-askpass"); p != "" && display != "" {
			return p, []string{msg}, nil
		}
	}
	return "", nil, ErrNoProvider
}

// Ask shows the dialog and returns the password.
func (e Env) Ask(ctx context.Context, req Request) ([]byte, error) {
	if req.Timeout <= 0 {
		req.Timeout = DefaultTimeout
	}
	name, args, err := e.Command(req)
	if err != nil {
		return nil, err
	}
	// Hard stop slightly after the dialog's own timeout; expiry is a cancel.
	ctx, cancel := context.WithTimeout(ctx, req.Timeout+5*time.Second)
	defer cancel()
	out, code, err := e.Run(ctx, name, args)
	if err != nil {
		return nil, ErrNoProvider
	}
	if code != 0 || ctx.Err() != nil {
		return nil, ErrCancelled
	}
	// The exit code alone tells a cancel from an answer: OK on an empty field
	// is an empty answer (an account or secret without a password), returned
	// as a non-nil empty slice so callers can tell it from "not asked yet".
	password := bytes.TrimSuffix(out, []byte("\n"))
	if bytes.ContainsAny(password, "\n\r\x00") {
		return nil, ErrCancelled
	}
	if password == nil {
		password = []byte{}
	}
	return password, nil
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

// macChoose is fixed: title, message, timeout, then the button labels arrive
// as argv items.
//
// The first button is the default button and nothing else. It must not also
// be named as the cancel button: macOS then gives it the Escape key only, and
// Return does nothing at all, so the user has to click a button to get rid of
// the dialog (seen on macOS 26). As the default button it is highlighted and
// Return presses it; Escape is not bound, and a timeout refuses.
const macChoose = `on run argv
activate
set bs to items 4 thru -1 of argv
set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons bs default button 1 with icon caution giving up after ((item 3 of argv) as integer)
if gave up of r then return ""
return button returned of r
end run`

// ChooseCommand picks the dialog program and its arguments for c.
func (e Env) ChooseCommand(c Choice) (string, []string, error) {
	seconds := int(c.Timeout / time.Second)
	if seconds <= 0 {
		seconds = int(DefaultTimeout / time.Second)
	}
	if len(c.Buttons) < 2 || len(c.Buttons) > 3 {
		return "", nil, errors.New("a choice needs 2 or 3 buttons")
	}
	switch e.GOOS {
	case "darwin":
		return "/usr/bin/osascript", append([]string{"-e", macChoose, c.Title, c.Text, strconv.Itoa(seconds)}, c.Buttons...), nil
	case "linux":
		if e.Getenv("DISPLAY") == "" && e.Getenv("WAYLAND_DISPLAY") == "" {
			return "", nil, ErrNoProvider
		}
		if p := e.Find("zenity"); p != "" {
			// --default-cancel gives the refusal the focus. Without it Return
			// presses the OK button, which is the approval here.
			args := []string{"--question", "--default-cancel", "--title=" + c.Title, "--text=" + pangoEscape(c.Text),
				"--timeout=" + strconv.Itoa(seconds), "--cancel-label=" + c.Buttons[0], "--ok-label=" + c.Buttons[1]}
			if len(c.Buttons) == 3 {
				args = append(args, "--extra-button="+c.Buttons[2])
			}
			return p, args, nil
		}
		if p := e.Find("kdialog"); p != "" {
			text := "<qt><pre>" + html.EscapeString(c.Text) + "</pre></qt>"
			if len(c.Buttons) == 3 {
				return p, []string{"--title", c.Title, "--yesnocancel", text, "--yes-label", c.Buttons[1],
					"--no-label", c.Buttons[2], "--cancel-label", c.Buttons[0]}, nil
			}
			return p, []string{"--title", c.Title, "--yesno", text, "--yes-label", c.Buttons[1],
				"--no-label", c.Buttons[0]}, nil
		}
	}
	// ssh-askpass cannot show buttons.
	return "", nil, ErrNoProvider
}

// Choose shows the dialog and returns the button index.
func (e Env) Choose(ctx context.Context, c Choice) (int, error) {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	name, args, err := e.ChooseCommand(c)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout+5*time.Second)
	defer cancel()
	out, code, err := e.Run(ctx, name, args)
	if err != nil {
		return 0, ErrNoProvider
	}
	if ctx.Err() != nil {
		return 0, nil
	}
	label := strings.TrimSuffix(string(out), "\n")
	switch {
	case e.GOOS == "darwin":
		if code != 0 {
			return 0, nil
		}
		for i, b := range c.Buttons {
			if label == b {
				return i, nil
			}
		}
		return 0, nil
	case strings.HasSuffix(name, "zenity"):
		if code == 0 {
			return 1, nil
		}
		if code == 1 && len(c.Buttons) == 3 && label == c.Buttons[2] {
			return 2, nil
		}
		return 0, nil
	default: // kdialog: 0 yes, 1 no, 2 cancel
		if code == 0 {
			return 1, nil
		}
		if code == 1 && len(c.Buttons) == 3 {
			return 2, nil
		}
		return 0, nil
	}
}
