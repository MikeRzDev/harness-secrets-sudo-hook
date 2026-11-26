package prompt

import (
	"bytes"
	"encoding/json"
	"html"
	"strconv"
	"strings"
)

// A backend is one way to show a Dialog: the program, its arguments and
// stdin, and how its output maps back to a Result. Each mapper below only
// translates; what the dialog is comes from the Dialog alone.
type backend struct {
	name  string
	args  []string
	stdin []byte
	parse func(out []byte, code int) Result
}

// backends lists the ways to show d here, in order. A backend whose Result is
// Unavailable (it showed nothing) hands over to the next one.
func (e Env) backends(d Dialog) ([]backend, error) {
	switch e.GOOS {
	case "darwin":
		var bs []backend
		if e.App != "" {
			bs = append(bs, appBackend(e.App, d))
		}
		return append(bs, osascriptBackend(d)), nil
	case "linux":
		display, wayland := e.Getenv("DISPLAY"), e.Getenv("WAYLAND_DISPLAY")
		if display == "" && wayland == "" {
			return nil, ErrNoProvider
		}
		if p := e.Find("zenity"); p != "" {
			return []backend{zenityBackend(p, d)}, nil
		}
		if p := e.Find("kdialog"); p != "" {
			return []backend{kdialogBackend(p, d)}, nil
		}
		// ssh-askpass has no buttons: it can only ask.
		if p := e.Find("ssh-askpass"); p != "" && display != "" && d.Kind == KindAsk {
			return []backend{{name: p, args: []string{d.Text}, parse: func(out []byte, code int) Result {
				if code != 0 {
					return Result{Outcome: Refused}
				}
				return Result{Outcome: Answered, Answer: line(out)}
			}}}, nil
		}
	}
	return nil, ErrNoProvider
}

// line is a program's output without its final newline.
func line(out []byte) string { return string(bytes.TrimSuffix(out, []byte("\n"))) }

// index is the position of label among the buttons, or -1.
func index(d Dialog, label string) int {
	for i, b := range d.Buttons {
		if b == label {
			return i
		}
	}
	return -1
}

// AppDialogFlag runs psudo as the psudo.app dialog helper.
const AppDialogFlag = "--dialog"

// appBackend shows d with psudo.app: the Dialog goes to it as JSON on stdin
// and the Result comes back as JSON on stdout. The answer travels only over
// that pipe, never in arguments or the environment. Anything but a clean
// Result (an older psudo.app, no window server) is Unavailable, so osascript
// shows the same dialog instead.
func appBackend(app string, d Dialog) backend {
	spec, _ := json.Marshal(d)
	return backend{name: app, args: []string{AppDialogFlag}, stdin: append(spec, '\n'),
		parse: func(out []byte, code int) Result {
			var r Result
			if code != 0 || json.Unmarshal(bytes.TrimSpace(out), &r) != nil {
				return Result{Outcome: Unavailable}
			}
			switch r.Outcome {
			case Answered, Refused, TimedOut:
				return r
			}
			return Result{Outcome: Unavailable}
		}}
}

// macDialog is fixed. Every part of the Dialog arrives as an argv item (data,
// never code): title, text, seconds, kind, the default and cancel buttons
// (1-based, 0 for none), then the button labels. It reports "T" when the
// dialog gave up, "A" and the answer, or "B" and the button pressed. The
// cancel button ends it with error -128.
const macDialog = `on run argv
set t to item 1 of argv
set m to item 2 of argv
set s to (item 3 of argv) as integer
set k to item 4 of argv
set d to (item 5 of argv) as integer
set c to (item 6 of argv) as integer
set bs to items 7 thru -1 of argv
activate
if k is "ask-hidden" then
set r to display dialog m with title t default answer "" with hidden answer buttons bs default button d cancel button c with icon caution giving up after s
else if k is "ask" then
set r to display dialog m with title t default answer "" buttons bs default button d cancel button c with icon caution giving up after s
else if c > 0 then
set r to display dialog m with title t buttons bs default button d cancel button c with icon caution giving up after s
else
set r to display dialog m with title t buttons bs default button d with icon caution giving up after s
end if
if gave up of r then return "T"
if k starts with "ask" then return "A" & (text returned of r)
return "B" & (button returned of r)
end run`

// osascriptBackend shows d with osascript.
func osascriptBackend(d Dialog) backend {
	kind := "choose"
	if d.Kind == KindAsk {
		kind = "ask"
		if d.Hidden {
			kind = "ask-hidden"
		}
	}
	args := append([]string{"-e", macDialog, d.Title, d.Text, strconv.Itoa(d.Seconds), kind,
		strconv.Itoa(d.Default + 1), strconv.Itoa(d.Cancel + 1)}, d.Buttons...)
	return backend{name: osascript, args: args, parse: func(out []byte, code int) Result {
		if code != 0 {
			return Result{Outcome: Refused}
		}
		s := line(out)
		switch {
		case s == "T":
			return Result{Outcome: TimedOut}
		case strings.HasPrefix(s, "A") && d.Kind == KindAsk:
			return Result{Outcome: Answered, Answer: s[1:]}
		case strings.HasPrefix(s, "B") && d.Kind == KindChoose:
			if i := index(d, s[1:]); i >= 0 {
				return Result{Outcome: Answered, Button: i}
			}
		}
		return Result{Outcome: Refused}
	}}
}

const osascript = "/usr/bin/osascript"

// pangoEscape escapes text for GTK markup labels (zenity --text).
func pangoEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// zenityBackend shows d with zenity. A choice has a refusal, an approval and
// an optional extra button: Buttons[0] is the refusal, and --default-cancel
// gives it the focus, as Default says. zenity exits 5 when it gives up.
func zenityBackend(p string, d Dialog) backend {
	timeout := "--timeout=" + strconv.Itoa(d.Seconds)
	if d.Kind == KindAsk {
		args := []string{"--entry"}
		if d.Hidden {
			args = append(args, "--hide-text")
		}
		args = append(args, "--title="+d.Title, "--text="+pangoEscape(d.Text), timeout)
		return backend{name: p, args: args, parse: func(out []byte, code int) Result {
			switch code {
			case 0:
				return Result{Outcome: Answered, Answer: line(out)}
			case 5:
				return Result{Outcome: TimedOut}
			}
			return Result{Outcome: Refused}
		}}
	}
	args := []string{"--question"}
	if d.Default == 0 {
		args = append(args, "--default-cancel")
	}
	args = append(args, "--title="+d.Title, "--text="+pangoEscape(d.Text), timeout,
		"--cancel-label="+d.Buttons[0], "--ok-label="+d.Buttons[1])
	if len(d.Buttons) == 3 {
		args = append(args, "--extra-button="+d.Buttons[2])
	}
	return backend{name: p, args: args, parse: func(out []byte, code int) Result {
		switch {
		case code == 0:
			return Result{Outcome: Answered, Button: 1}
		case code == 1 && len(d.Buttons) == 3 && line(out) == d.Buttons[2]:
			return Result{Outcome: Answered, Button: 2}
		case code == 5:
			return Result{Outcome: TimedOut}
		}
		return Result{Outcome: Refused}
	}}
}

// kdialogBackend shows d with kdialog. <qt><pre> forces rich text, so the
// escaped text renders verbatim. kdialog cannot pick the default button or
// give up after a time: there Return may press an approval.
func kdialogBackend(p string, d Dialog) backend {
	text := "<qt><pre>" + html.EscapeString(d.Text) + "</pre></qt>"
	if d.Kind == KindAsk {
		mode := "--inputbox"
		if d.Hidden {
			mode = "--password"
		}
		return backend{name: p, args: []string{"--title", d.Title, mode, text}, parse: func(out []byte, code int) Result {
			if code != 0 {
				return Result{Outcome: Refused}
			}
			return Result{Outcome: Answered, Answer: line(out)}
		}}
	}
	var args []string
	if len(d.Buttons) == 3 {
		args = []string{"--title", d.Title, "--yesnocancel", text, "--yes-label", d.Buttons[1],
			"--no-label", d.Buttons[2], "--cancel-label", d.Buttons[0]}
	} else {
		args = []string{"--title", d.Title, "--yesno", text, "--yes-label", d.Buttons[1], "--no-label", d.Buttons[0]}
	}
	// 0 yes, 1 no, 2 cancel.
	return backend{name: p, args: args, parse: func(out []byte, code int) Result {
		switch {
		case code == 0:
			return Result{Outcome: Answered, Button: 1}
		case code == 1 && len(d.Buttons) == 3:
			return Result{Outcome: Answered, Button: 2}
		}
		return Result{Outcome: Refused}
	}}
}
