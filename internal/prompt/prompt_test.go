package prompt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
)

const evil = `rm -rf "/tmp/x" ; echo '$(id)' <b>bold</b> & "quote" \" end tell` + "\n\u202eline two"

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

func names(t *testing.T, e Env, d Dialog) []string {
	t.Helper()
	bs, err := e.backends(d)
	if err != nil {
		t.Fatalf("%s: %v", e.GOOS, err)
	}
	var out []string
	for _, b := range bs {
		out = append(out, b.name)
	}
	return out
}

func TestDialogSelection(t *testing.T) {
	ask := Request{Title: "t", Command: "c"}.dialog()
	for _, tc := range []struct {
		e    Env
		want []string
	}{
		{env("linux", ":0", "", "zenity"), []string{"/usr/bin/zenity"}},
		{env("linux", "", "wayland-0", "kdialog"), []string{"/usr/bin/kdialog"}},
		{env("linux", ":0", "", "ssh-askpass"), []string{"/usr/bin/ssh-askpass"}},
		{env("darwin", "", "", ""), []string{osascript}},
	} {
		if got := names(t, tc.e, ask); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%+v: got %q", tc.want, got)
		}
	}
	// With psudo.app installed it comes first, and osascript stays behind it.
	mac := env("darwin", "", "", "")
	mac.App = AppExecutable
	if got := names(t, mac, ask); !reflect.DeepEqual(got, []string{AppExecutable, osascript}) {
		t.Errorf("macOS with psudo.app: %q", got)
	}
	for _, e := range []Env{env("linux", "", "", "zenity"), env("linux", "", "wayland-0", "ssh-askpass"),
		env("linux", ":0", "", ""), env("windows", "", "", "")} {
		if _, err := e.backends(ask); !errors.Is(err, ErrNoProvider) {
			t.Errorf("%+v: %v", e.GOOS, err)
		}
	}
}

// The rules of every dialog live in the Dialog, once.
func TestDialogRules(t *testing.T) {
	a := Request{Title: "t", Host: "h", Command: "c", Timeout: 30 * time.Second}.dialog()
	if a.Kind != KindAsk || !a.Hidden || !reflect.DeepEqual(a.Buttons, []string{"Cancel", "OK"}) ||
		a.Default != 1 || a.Cancel != 0 || a.Seconds != 30 || a.Text != Message("h", "c") {
		t.Errorf("answer dialog %+v", a)
	}
	c := Choice{Title: "t", Text: "x", Buttons: []string{"Deny", "Allow"}}.dialog()
	// The refusal is the default button and not the cancel button: with both,
	// macOS gives it Escape only and Return does nothing.
	if c.Kind != KindChoose || c.Default != 0 || c.Cancel != -1 || c.Seconds != int(DefaultTimeout/time.Second) {
		t.Errorf("choice dialog %+v", c)
	}
	for _, bad := range []Dialog{
		{Kind: KindChoose, Buttons: []string{"one"}, Cancel: -1, Seconds: 1},
		{Kind: KindChoose, Buttons: []string{"a", "b", "c", "d"}, Cancel: -1, Seconds: 1},
		{Kind: KindChoose, Buttons: []string{"a", "a"}, Cancel: -1, Seconds: 1},
		{Kind: KindChoose, Buttons: []string{"a", "b"}, Default: 2, Cancel: -1, Seconds: 1},
		{Kind: KindAsk, Buttons: []string{"a", "b"}, Default: 1, Cancel: -1, Seconds: 1},
		{Kind: KindAsk, Buttons: []string{"a", "b"}, Default: 1, Cancel: 1, Seconds: 1},
		{Kind: "other", Buttons: []string{"a", "b"}, Cancel: -1, Seconds: 1},
		{Kind: KindChoose, Buttons: []string{"a", "b"}, Cancel: -1},
	} {
		if bad.check() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// realDialogs are the kinds of dialog psudo shows.
func realDialogs() []Dialog {
	return []Dialog{
		Request{Title: "sudo password (Claude Code)", Host: "web-1", Command: evil}.dialog(),
		Request{Title: "SSH login (Claude Code)", Text: LoginMessage("web-1", "Password:")}.dialog(),
		Request{Title: "Secret needed", Text: "Enter the value of stripe-api-key", Timeout: 270 * time.Second}.dialog(),
		Choice{Title: "Secret request", Text: evil, Buttons: []string{"Deny", "Allow once", "Allow for 10 min"}}.dialog(),
		Choice{Title: "Keep the secret?", Text: "x", Buttons: []string{"This session only", "Save"}}.dialog(),
		Choice{Title: "Program changed", Text: "y", Buttons: []string{"Deny", "Allow"}}.dialog(),
	}
}

// The two macOS mappers carry the same dialog: decoding what each one is
// given gives back the Dialog it was made from, field for field.
func TestMacMappersCarryTheSameDialog(t *testing.T) {
	for _, d := range realDialogs() {
		if err := d.check(); err != nil {
			t.Fatalf("%q: %v", d.Title, err)
		}
		// psudo.app: JSON on stdin, nothing from the dialog in its arguments.
		app := appBackend(AppExecutable, d)
		if !reflect.DeepEqual(app.args, []string{AppDialogFlag}) {
			t.Errorf("psudo.app argv %q", app.args)
		}
		var fromApp Dialog
		if err := json.Unmarshal(app.stdin, &fromApp); err != nil || !reflect.DeepEqual(fromApp, d) {
			t.Errorf("psudo.app got %+v, want %+v (%v)", fromApp, d, err)
		}
		// osascript: every field as an argv item after the fixed script.
		o := osascriptBackend(d).args
		if o[0] != "-e" || o[1] != macDialog {
			t.Fatalf("osascript argv %q", o[:2])
		}
		sec, _ := strconv.Atoi(o[4])
		def, _ := strconv.Atoi(o[6])
		cancel, _ := strconv.Atoi(o[7])
		fromScript := Dialog{Kind: KindChoose, Title: o[2], Text: o[3], Seconds: sec,
			Default: def - 1, Cancel: cancel - 1, Buttons: o[8:]}
		if strings.HasPrefix(o[5], "ask") {
			fromScript.Kind, fromScript.Hidden = KindAsk, o[5] == "ask-hidden"
		}
		if !reflect.DeepEqual(fromScript, d) {
			t.Errorf("osascript got %+v, want %+v", fromScript, d)
		}
	}
}

// Model-controlled text must be passed as data and rendered verbatim.
func TestCommandTextIsDataNotCode(t *testing.T) {
	d := Request{Title: "sudo password (Claude Code)", Host: "web-1", Command: evil, Timeout: 30 * time.Second}.dialog()
	o := osascriptBackend(d).args
	if o[2] != d.Title || o[3] != Message("web-1", evil) || o[4] != "30" || strings.Contains(macDialog, "web-1") {
		t.Fatalf("osascript argv %q", o)
	}
	z := zenityBackend("/usr/bin/zenity", d).args
	if text := z[3]; strings.Contains(text, "<b>") || !strings.Contains(text, "&lt;b&gt;bold&lt;/b&gt;") || !strings.Contains(text, "&amp;") {
		t.Fatalf("zenity text not escaped: %q", text)
	}
	k := kdialogBackend("/usr/bin/kdialog", d).args
	if !strings.HasPrefix(k[3], "<qt><pre>") || strings.Contains(k[3], "<b>") || k[2] != "--password" {
		t.Fatalf("kdialog argv %q", k)
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
		{"As3cret\n", 0, nil, nil, "s3cret"},
		{"", 1, nil, ErrCancelled, ""}, // the cancel button
		{"T\n", 0, nil, ErrCancelled, ""},
		{"A\n", 0, nil, nil, ""}, // OK on an empty field
		{"A", 0, nil, nil, ""},
		{"Aa\nb\n", 0, nil, ErrCancelled, ""},
		{"garbage\n", 0, nil, ErrCancelled, ""},
		{"", -1, errors.New("not found"), ErrNoProvider, ""},
	} {
		e := env("darwin", "", "", "")
		e.Run = func(context.Context, string, []string, []byte) ([]byte, int, error) {
			return []byte(tc.out), tc.code, tc.err
		}
		pw, err := e.Ask(context.Background(), Request{Title: "t", Command: "c"})
		if !errors.Is(err, tc.want) || string(pw) != tc.pw || (err == nil && pw == nil) {
			t.Errorf("%+v: got %q %v", tc, pw, err)
		}
	}
}

// psudo.app answers first. Only when it shows nothing (an older app, no
// window server, not started) does osascript show the same dialog; a refusal
// or a timeout in psudo.app is final.
func TestAppFallsBackToOsascriptOnlyWhenItShowedNothing(t *testing.T) {
	result := func(r Result) string { b, _ := json.Marshal(r); return string(b) + "\n" }
	for _, tc := range []struct {
		appOut  string
		appCode int
		appErr  error
		want    []byte
		wantErr error
		calls   int
	}{
		{result(Result{Outcome: Answered, Answer: "pw"}), 0, nil, []byte("pw"), nil, 1},
		{result(Result{Outcome: Refused}), 0, nil, nil, ErrCancelled, 1},
		{result(Result{Outcome: TimedOut}), 0, nil, nil, ErrCancelled, 1},
		{"", 2, nil, []byte("from osascript"), nil, 2},
		{"not json", 0, nil, []byte("from osascript"), nil, 2},
		{result(Result{Outcome: Unavailable}), 0, nil, []byte("from osascript"), nil, 2},
		{"", -1, errors.New("missing"), []byte("from osascript"), nil, 2},
	} {
		e := env("darwin", "", "", "")
		e.App = AppExecutable
		var calls []string
		e.Run = func(_ context.Context, name string, args []string, stdin []byte) ([]byte, int, error) {
			calls = append(calls, name)
			if name == AppExecutable {
				if !bytes.Contains(stdin, []byte(`"kind":"ask"`)) {
					t.Errorf("psudo.app stdin %s", stdin)
				}
				return []byte(tc.appOut), tc.appCode, tc.appErr
			}
			return []byte("Afrom osascript\n"), 0, nil
		}
		pw, err := e.Ask(context.Background(), Request{Title: "t", Command: "c"})
		if !errors.Is(err, tc.wantErr) || !bytes.Equal(pw, tc.want) || len(calls) != tc.calls {
			t.Errorf("%+v: got %q %v after %q", tc, pw, err, calls)
		}
	}
}

func TestAskHardTimeoutIsCancel(t *testing.T) {
	e := env("darwin", "", "", "")
	e.Run = func(ctx context.Context, _ string, _ []string, _ []byte) ([]byte, int, error) {
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
		{"darwin", "", 3, outcome{"BAllow once\n", 0}, 1},
		{"darwin", "", 3, outcome{"BAllow for 10 min\n", 0}, 2},
		{"darwin", "", 3, outcome{"BDeny\n", 0}, 0},
		{"darwin", "", 3, outcome{"T\n", 0}, 0},          // gave up
		{"darwin", "", 3, outcome{"", 1}, 0},             // closed
		{"darwin", "", 3, outcome{"BSomething\n", 0}, 0}, // not a button
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
		e.Run = func(_ context.Context, name string, args []string, _ []byte) ([]byte, int, error) {
			argv = args
			return []byte(tc.got.out), tc.got.code, nil
		}
		got, err := e.Choose(context.Background(), Choice{Title: "t", Text: evil, Buttons: buttons[:tc.n]})
		if err != nil || got != tc.want {
			t.Errorf("%+v: got %d %v", tc, got, err)
		}
		// Default button 1 (Deny), no cancel button, then the labels.
		if tc.goos == "darwin" && (argv[1] != macDialog || argv[3] != evil || argv[5] != "choose" ||
			argv[6] != "1" || argv[7] != "0" || argv[8] != "Deny") {
			t.Errorf("osascript argv %q", argv)
		}
		// The refusal has the focus, so Return does not approve.
		if tc.tool == "zenity" && argv[1] != "--default-cancel" {
			t.Errorf("zenity argv %q", argv)
		}
	}
	// A login prompt comes from the SSH server: hidden characters are shown.
	if msg := LoginMessage("web-1", "Password\u202e:\x1b[2J "); !strings.Contains(msg, `Password\u{202E}:\u{001B}[2J`) {
		t.Errorf("login message %q", msg)
	}
	if _, err := env("linux", ":0", "", "ssh-askpass").Choose(context.Background(), Choice{Buttons: buttons}); !errors.Is(err, ErrNoProvider) {
		t.Fatal("ssh-askpass cannot show buttons")
	}
	if _, err := env("darwin", "", "", "").Choose(context.Background(), Choice{Buttons: buttons[:1]}); !errors.Is(err, errButtons) {
		t.Fatalf("one button: %v", err)
	}
}

// The helper refuses anything but one valid Dialog, before drawing anything.
func TestServeAppRejectsInvalidInput(t *testing.T) {
	for _, in := range []string{"", "not json", `{"kind":"choose","buttons":["a"],"cancel":-1,"seconds":5}`,
		`{"kind":"ask","buttons":["Cancel","OK"],"default":1,"cancel":-1,"seconds":5}`} {
		var out bytes.Buffer
		if code := ServeApp(strings.NewReader(in), &out); code != 2 || out.Len() != 0 {
			t.Errorf("%q: exit %d, output %q", in, code, out.String())
		}
	}
}

// A dialog program is started with the account's own HOME, whatever the
// caller of psudo put in the environment.
func TestDialogProgramDoesNotGetTheCallersHome(t *testing.T) {
	t.Setenv("HOME", "/tmp/not-my-home")
	out, code, err := runDialog(context.Background(), "/usr/bin/env", nil, nil)
	if err != nil || code != 0 {
		t.Fatalf("%v %d", err, code)
	}
	if strings.Contains(string(out), "HOME=/tmp/not-my-home") && cache.Home() != "/tmp/not-my-home" {
		t.Fatalf("the caller's HOME reached the dialog program:\n%s", out)
	}
}

// The test app is used only when it holds the same build as the running
// psudo, which is told by the Go build ID: the ad hoc signature changes the
// app's bytes but not that.
func TestGoBuildID(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if id, err := goBuildID(self); err != nil || !strings.Contains(id, "/") {
		t.Fatalf("own build ID %q %v", id, err)
	}
	other := filepath.Join(t.TempDir(), "psudo")
	os.WriteFile(other, []byte("#!/bin/sh\necho not psudo\n"), 0o755)
	if _, err := goBuildID(other); err == nil {
		t.Fatal("found a build ID in a script")
	}
}

// A test app from another build is not used, whatever its file holds; a copy
// of the same build is, also when its bytes differ after its build ID (as
// the ad hoc signature makes them).
func TestAppOfAnotherBuildIsNotUsed(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	signed := append(append([]byte(nil), body...), "ad hoc signature"...)
	if !sameBuild(self, write("same", signed, 0o755)) {
		t.Fatal("a copy of this build was refused")
	}
	if sameBuild(self, write("noexec", body, 0o644)) {
		t.Fatal("a file that is not executable was used")
	}
	if sameBuild(self, write("script", []byte("#!/bin/sh\n"), 0o755)) {
		t.Fatal("a script was used")
	}
	// Another Go program: the go command itself has a build ID of its own.
	goCmd := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := goBuildID(goCmd); err != nil {
		t.Skipf("no Go build ID in %s: %v", goCmd, err)
	}
	if sameBuild(self, goCmd) {
		t.Fatal("another Go build was used")
	}
	if sameBuild(self, filepath.Join(dir, "missing")) {
		t.Fatal("a missing app was used")
	}
}

// A long command must not push the answer field and the buttons off the
// screen: no backend scrolls its text.
func TestLongTextFitsTheDialog(t *testing.T) {
	rowsOf := func(s string) int { return rowsOf(strings.Split(s, "\n")) }
	var cmd strings.Builder
	cmd.WriteString("sh -c 'set -eu")
	for i := 1; i <= 80; i++ {
		fmt.Fprintf(&cmd, "\ninstall -d -m 700 -o $U -g $U /home/$U/step-%d", i)
	}
	cmd.WriteString("\nsystemctl daemon-reload'")

	text := Message("rivendell", cmd.String())
	d := Request{Title: "sudo password (Claude Code)", Host: "rivendell", Command: cmd.String()}.dialog()
	if rows := rowsOf(d.Text); rows > textRows {
		t.Fatalf("%d rows, want at most %d:\n%s", rows, textRows, d.Text)
	}
	lines := strings.Split(text, "\n")
	if !strings.HasPrefix(d.Text, "Host: rivendell\n\nCommand:\nsh -c 'set -eu\n") ||
		!strings.HasSuffix(d.Text, "systemctl daemon-reload'\n\n"+lines[len(lines)-1]) {
		t.Fatalf("the host, the start and the end of the command must stay:\n%s", d.Text)
	}
	shown := strings.Split(d.Text, "\n")
	hidden := len(lines) - (len(shown) - 1)
	if !strings.Contains(d.Text, fmt.Sprintf("[… %d more lines not shown …]", hidden)) {
		t.Fatalf("want a marker for %d hidden lines:\n%s", hidden, d.Text)
	}

	// Choices are fitted the same way.
	if c := (Choice{Title: "t", Text: text, Buttons: []string{"Deny", "Allow"}}).dialog(); c.Text != d.Text {
		t.Fatalf("a choice must be fitted like an answer dialog")
	}

	// One huge line keeps its start and its end, and the cut is marked.
	huge := "cp /src/" + strings.Repeat("x", 5000) + " /dst/target"
	one := fitText("Host: h\n\nCommand:\n" + huge + "\n\nEnter it.")
	if rowsOf(one) > textRows || !strings.Contains(one, "cp /src/xx") || !strings.Contains(one, "x … x") ||
		!strings.HasSuffix(one, "x /dst/target\n\nEnter it.") {
		t.Fatalf("a huge line must keep both ends:\n%s", one)
	}

	// A long last line (the rule a secret dialog adds) keeps its end too.
	var body strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&body, "line %d\n", i)
	}
	rule := "This also adds a rule to config.json: " + strings.Repeat("/long/path", 30) + "/show-secret"
	got := fitText(body.String() + rule)
	if rowsOf(got) > textRows || !strings.HasSuffix(got, "/show-secret") ||
		!strings.Contains(got, "This also adds a rule") {
		t.Fatalf("the end of the last line must stay:\n%s", got)
	}

	// Long paths are cut before any line is hidden or any prose is cut, so
	// every statement of a secret dialog stays.
	dir := "/private/tmp/" + strings.Repeat("deep-folder-name/", 14)
	prose := "psudo has no value for the secret. Type or paste it to run this command. psudo then asks where to keep it; " +
		"unless you choose otherwise, it is not kept beyond this session."
	secret := prose + "\n\nHost: this computer\nFolder: " + dir + "proj\nCommand:\n" + dir + "proj/show-secret X\n\n" +
		"This also adds a rule to config.json:\n" + dir + "proj/show-secret\nmay use \"x\" as X on this computer.\n" + prose
	got = fitText(secret)
	if rowsOf(got) > textRows || strings.Contains(got, "not shown") || !strings.Contains(got, prose) ||
		!strings.Contains(got, "This also adds a rule to config.json:\n") || !strings.Contains(got, "proj/show-secret\nmay use") ||
		!strings.Contains(got, " … ") {
		t.Fatalf("paths must be cut first and every line kept:\n%s", got)
	}

	// A text that fits is left exactly as it is.
	if short := Message("web-1", "id -u"); fitText(short) != short {
		t.Fatalf("a short text changed")
	}
}
