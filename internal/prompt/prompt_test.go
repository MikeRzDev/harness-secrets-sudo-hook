package prompt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
)

const evil = `rm -rf "/tmp/x" ; echo '$(id)' <b>bold</b> & "quote" \" end tell`

func env(goos, display, wayland, available string) Env {
	return Env{GOOS: goos,
		Getenv: func(k string) string {
			return map[string]string{"DISPLAY": display, "WAYLAND_DISPLAY": wayland}[k]
		},
		Find: func(name string) string {
			if name == available {
				return "/usr/bin/" + name
			}
			return ""
		}}
}

func TestDialogSelection(t *testing.T) {
	for _, tc := range []struct{ goos, display, wayland, tool, want string }{
		{"linux", ":0", "", "zenity", "/usr/bin/zenity"},
		{"linux", "", "wayland-0", "kdialog", "/usr/bin/kdialog"},
		{"linux", ":0", "", "ssh-askpass", "/usr/bin/ssh-askpass"},
		{"darwin", "", "", "", "/usr/bin/osascript"},
	} {
		name, _, err := env(tc.goos, tc.display, tc.wayland, tc.tool).Command(Request{Title: "t", Command: "c"})
		if err != nil || name != tc.want {
			t.Errorf("%+v: got %s %v", tc, name, err)
		}
	}
	for _, e := range []Env{env("linux", "", "", "zenity"), env("linux", "", "wayland-0", "ssh-askpass"),
		env("linux", ":0", "", ""), env("windows", "", "", "")} {
		if _, _, err := e.Command(Request{}); !errors.Is(err, ErrNoProvider) {
			t.Errorf("%+v: %v", e.GOOS, err)
		}
	}
}

// Model-controlled text must be passed as data and rendered verbatim.
func TestCommandTextIsDataNotCode(t *testing.T) {
	req := Request{Title: "sudo password (Claude Code)", Host: "web-1", Command: evil, Timeout: 30 * time.Second}
	_, args, _ := env("darwin", "", "", "").Command(req)
	if args[1] != macScript || args[2] != req.Title || args[3] != Message("web-1", evil) || args[4] != "30" {
		t.Fatalf("osascript argv %q", args)
	}
	_, args, _ = env("linux", ":0", "", "zenity").Command(req)
	text := args[3]
	if strings.Contains(text, "<b>") || !strings.Contains(text, "&lt;b&gt;bold&lt;/b&gt;") || !strings.Contains(text, "&amp;") {
		t.Fatalf("zenity text not escaped: %q", text)
	}
	_, args, _ = env("linux", ":0", "", "kdialog").Command(req)
	if !strings.HasPrefix(args[3], "<qt><pre>") || strings.Contains(args[3], "<b>") {
		t.Fatalf("kdialog text not escaped: %q", args[3])
	}
	if !strings.Contains(Message("web-1", evil), "Host: web-1") || !strings.Contains(Message("", "x"), "this computer") {
		t.Fatal("message lacks host label")
	}
}

func TestAskOutcomes(t *testing.T) {
	for _, tc := range []struct {
		out  string
		code int
		err  error
		want error
		pw   string
	}{
		{"s3cret\n", 0, nil, nil, "s3cret"},
		{"", 1, nil, ErrCancelled, ""},
		{"", 5, nil, ErrCancelled, ""}, // zenity timeout
		{"\n", 0, nil, nil, ""},        // OK on an empty field
		{"", 0, nil, nil, ""},
		{"a\nb\n", 0, nil, ErrCancelled, ""},
		{"", -1, errors.New("not found"), ErrNoProvider, ""},
	} {
		e := env("darwin", "", "", "")
		e.Run = func(context.Context, string, []string) ([]byte, int, error) { return []byte(tc.out), tc.code, tc.err }
		pw, err := e.Ask(context.Background(), Request{Title: "t", Command: "c"})
		if !errors.Is(err, tc.want) || string(pw) != tc.pw || (err == nil && pw == nil) {
			t.Errorf("%+v: got %q %v", tc, pw, err)
		}
	}
}

func TestAskHardTimeoutIsCancel(t *testing.T) {
	e := env("darwin", "", "", "")
	e.Run = func(ctx context.Context, _ string, _ []string) ([]byte, int, error) {
		<-ctx.Done()
		return nil, 1, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := e.Ask(ctx, Request{Timeout: time.Second}); !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
}

func TestChoose(t *testing.T) {
	buttons := []string{"Deny", "Allow once", "Allow for 10 min"}
	type outcome struct {
		out  string
		code int
	}
	for _, tc := range []struct {
		goos, tool string
		n          int
		got        outcome
		want       int
	}{
		{"darwin", "", 3, outcome{"Allow once\n", 0}, 1},
		{"darwin", "", 3, outcome{"Allow for 10 min\n", 0}, 2},
		{"darwin", "", 3, outcome{"", 0}, 0}, // gave up
		{"darwin", "", 3, outcome{"", 1}, 0}, // Deny is the cancel button
		{"linux", "zenity", 3, outcome{"", 0}, 1},
		{"linux", "zenity", 3, outcome{"Allow for 10 min\n", 1}, 2},
		{"linux", "zenity", 3, outcome{"", 1}, 0},
		{"linux", "zenity", 3, outcome{"", 5}, 0}, // timeout
		{"linux", "kdialog", 3, outcome{"", 0}, 1},
		{"linux", "kdialog", 3, outcome{"", 1}, 2},
		{"linux", "kdialog", 3, outcome{"", 2}, 0},
		{"linux", "kdialog", 2, outcome{"", 1}, 0},
	} {
		e := env(tc.goos, ":0", "", tc.tool)
		var argv []string
		e.Run = func(_ context.Context, name string, args []string) ([]byte, int, error) {
			argv = args
			return []byte(tc.got.out), tc.got.code, nil
		}
		got, err := e.Choose(context.Background(), Choice{Title: "t", Text: evil, Buttons: buttons[:tc.n]})
		if err != nil || got != tc.want {
			t.Errorf("%+v: got %d %v", tc, got, err)
		}
		if tc.goos == "darwin" && (argv[1] != macChoose || argv[3] != evil || argv[5] != "Deny") {
			t.Errorf("osascript argv %q", argv)
		}
		// The refusal has the focus, so Return does not approve.
		if tc.tool == "zenity" && argv[1] != "--default-cancel" {
			t.Errorf("zenity argv %q", argv)
		}
	}
	// On macOS the first button is the default button and must not also be
	// the cancel button: with both, Return does nothing and the user has to
	// click a button to get rid of the dialog.
	if !strings.Contains(macChoose, "default button 1") || strings.Contains(macChoose, "cancel button") {
		t.Errorf("the macOS choice dialog must name button 1 as the default button only:\n%s", macChoose)
	}
	// A login prompt comes from the SSH server: hidden characters are shown.
	if msg := LoginMessage("web-1", "Password\u202e:\x1b[2J "); !strings.Contains(msg, `Password\u{202E}:\u{001B}[2J`) {
		t.Errorf("login message %q", msg)
	}
	if _, err := env("linux", ":0", "", "ssh-askpass").Choose(context.Background(), Choice{Buttons: buttons}); !errors.Is(err, ErrNoProvider) {
		t.Fatal("ssh-askpass cannot show buttons")
	}
}

// A dialog program is started with the account's own HOME, whatever the
// caller of psudo put in the environment.
func TestDialogProgramDoesNotGetTheCallersHome(t *testing.T) {
	t.Setenv("HOME", "/tmp/not-my-home")
	out, code, err := runDialog(context.Background(), "/usr/bin/env", nil)
	if err != nil || code != 0 {
		t.Fatalf("%v %d", err, code)
	}
	if strings.Contains(string(out), "HOME=/tmp/not-my-home") && cache.Home() != "/tmp/not-my-home" {
		t.Fatalf("the caller's HOME reached the dialog program:\n%s", out)
	}
}
