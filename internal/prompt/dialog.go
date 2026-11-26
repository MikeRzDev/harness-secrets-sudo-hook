package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Dialog is the one definition of a dialog. Every backend (psudo.app,
// osascript, zenity, kdialog, ssh-askpass) draws it from here and decides
// nothing itself: which buttons there are, in which order, which one Return
// and Escape press, whether the answer is hidden and when the dialog gives
// up. A rule about dialogs belongs in request() or choice() below, never in
// one backend.
type Dialog struct {
	Kind    Kind     `json:"kind"`
	Title   string   `json:"title"`
	Text    string   `json:"text"`             // shown verbatim, as data
	Hidden  bool     `json:"hidden,omitempty"` // Ask: the answer is typed hidden
	Buttons []string `json:"buttons"`          // left to right
	Default int      `json:"default"`          // the button Return presses
	Cancel  int      `json:"cancel"`           // the button Escape presses, or -1
	Seconds int      `json:"seconds"`          // the dialog gives up after this
}

// Kind is what a dialog asks for.
type Kind string

const (
	// KindAsk asks for a typed answer.
	KindAsk Kind = "ask"
	// KindChoose asks for one of its buttons.
	KindChoose Kind = "choose"
)

// Result is what a backend reports, whatever the backend.
type Result struct {
	Outcome Outcome `json:"outcome"`
	Answer  string  `json:"answer,omitempty"` // KindAsk, when answered
	Button  int     `json:"button"`           // the button pressed, when answered
}

// Outcome is how a dialog ended.
type Outcome string

const (
	// Answered: OK with a typed answer (possibly empty), or a button pressed.
	Answered Outcome = "answered"
	// Refused: the cancel button, or the dialog was closed.
	Refused Outcome = "refused"
	// TimedOut: the dialog gave up after Seconds.
	TimedOut Outcome = "timedout"
	// Unavailable: no dialog was shown, so the next backend may try.
	Unavailable Outcome = "unavailable"
)

// Labels of the buttons of every KindAsk dialog.
const (
	askCancel = "Cancel"
	askOK     = "OK"
)

func seconds(d time.Duration) int {
	if s := int(d / time.Second); s > 0 {
		return s
	}
	return int(DefaultTimeout / time.Second)
}

// The text of a dialog is at most textRows rows of about textCols
// characters. No backend scrolls its text (osascript, NSAlert, zenity and
// kdialog all grow the window instead), so a longer text pushes the answer
// field and the buttons off the screen.
const (
	textRows = 30
	textCols = 50
)

// hiddenLines marks the lines fitText leaves out. They are part of what the
// user is asked about (they run too), and the whole text is in the agent's
// tool call.
const hiddenLines = "[… %d more lines not shown here. They are part of it too; the whole command is in the agent's tool call …]"

// lineRows is the most rows one line of a shortened text takes at first.
const lineRows = 4

// fitText shortens a text that is too long for a dialog. First long lines
// get shorter, a row at a time down to one row, paths and other long words
// before prose. Each keeps its start and its end with " … " in between, so
// every line stays and no statement of the dialog is lost. If the text is
// still too long (a command of many lines), it keeps its first lines (the
// host and the start of the command) and its last lines (the end of the
// command and what the dialog asks for), with a line saying how many lines
// are not shown in between.
func fitText(s string) string {
	lines := strings.Split(s, "\n")
	if rowsOf(lines) <= textRows {
		return s
	}
	// Shorten the longest line by a row until the text fits or every line
	// takes one row.
	allowed := make([]int, len(lines))
	cut := make([]string, len(lines))
	for i, l := range lines {
		allowed[i] = min(rows(l), lineRows)
		cut[i] = cutLine(l, allowed[i])
	}
	// Text without spaces (a path, a token) goes first, prose last.
	weight := func(l string) int { return utf8.RuneCountInString(l) - 8*strings.Count(l, " ") }
	for rowsOf(cut) > textRows {
		longest := -1
		for i := range cut {
			if allowed[i] > 1 && (longest < 0 || weight(cut[i]) > weight(cut[longest])) {
				longest = i
			}
		}
		if longest < 0 {
			break
		}
		allowed[longest]--
		cut[longest] = cutLine(lines[longest], allowed[longest])
	}
	if rowsOf(cut) <= textRows {
		return strings.Join(cut, "\n")
	}
	for i, l := range lines {
		lines[i] = cutLine(l, lineRows)
	}
	budget := textRows - rows(fmt.Sprintf(hiddenLines, 99999)) // the marker's rows
	tailRows := budget / 3
	tail := len(lines)
	for tail > 0 && rows(lines[tail-1]) <= tailRows {
		tailRows -= rows(lines[tail-1])
		tail--
	}
	headRows := budget - (budget/3 - tailRows)
	var head []string
	for _, l := range lines[:tail] {
		if r := rows(l); r <= headRows {
			head = append(head, l)
			headRows -= r
			continue
		}
		if headRows > 0 {
			head = append(head, cutLine(l, headRows))
		}
		break
	}
	if n := tail - len(head); n > 0 {
		head = append(head, fmt.Sprintf(hiddenLines, n))
	}
	return strings.Join(append(head, lines[tail:]...), "\n")
}

// rows is how many rows a line takes in a dialog.
func rows(l string) int { return max(1, (utf8.RuneCountInString(l)+textCols-1)/textCols) }

func rowsOf(lines []string) int {
	n := 0
	for _, l := range lines {
		n += rows(l)
	}
	return n
}

// cutLine shortens a line to at most n rows, keeping its start and its end.
func cutLine(l string, n int) string {
	if rows(l) <= n {
		return l
	}
	r := []rune(l)
	keep := n*textCols - 3
	front := keep * 2 / 3
	return string(r[:front]) + " … " + string(r[len(r)-(keep-front):])
}

// request is the dialog for a Request. Every answer psudo asks for is a
// password, a code or a secret value, so it is typed hidden. OK is the
// default button and Cancel the cancel button.
func (req Request) dialog() Dialog {
	return Dialog{Kind: KindAsk, Title: req.Title, Text: fitText(req.message()), Hidden: true,
		Buttons: []string{askCancel, askOK}, Default: 1, Cancel: 0, Seconds: seconds(req.Timeout)}
}

// dialog is the dialog for a Choice. Buttons[0] is the refusal and the
// default button, so Return refuses. It is not also the cancel button: on
// macOS a button that is both gets the Escape key only, and Return does
// nothing at all (seen on macOS 26). A timeout refuses.
func (c Choice) dialog() Dialog {
	return Dialog{Kind: KindChoose, Title: c.Title, Text: fitText(c.Text), Buttons: c.Buttons,
		Default: 0, Cancel: -1, Seconds: seconds(c.Timeout)}
}

var errButtons = errors.New("a choice needs 2 or 3 buttons")

// check rejects a dialog that a backend could not draw as defined. The
// psudo.app helper checks again, since its dialog arrives over a pipe.
func (d Dialog) check() error {
	switch d.Kind {
	case KindAsk:
		if len(d.Buttons) != 2 || d.Cancel < 0 {
			return errors.New("an answer dialog needs two buttons and a cancel button")
		}
	case KindChoose:
		if len(d.Buttons) < 2 || len(d.Buttons) > 3 {
			return errButtons
		}
	default:
		return errors.New("unknown dialog kind")
	}
	seen := map[string]bool{}
	for _, b := range d.Buttons {
		if b == "" || seen[b] {
			return errors.New("button labels must be unique and not empty")
		}
		seen[b] = true
	}
	if d.Default < 0 || d.Default >= len(d.Buttons) || d.Cancel >= len(d.Buttons) || d.Cancel == d.Default {
		return errors.New("invalid default or cancel button")
	}
	if d.Seconds <= 0 {
		return errors.New("a dialog needs a timeout")
	}
	return nil
}

// Check is check for the psudo.app helper.
func (d Dialog) Check() error { return d.check() }

// answer turns a Result into what Ask returns. OK on an empty field is an
// empty answer (an account or secret without a password), returned as a
// non-nil empty slice so callers can tell it from "not asked yet".
func (r Result) answer() ([]byte, error) {
	switch r.Outcome {
	case Answered:
		pw := []byte(r.Answer)
		if bytes.ContainsAny(pw, "\n\r\x00") {
			return nil, ErrCancelled
		}
		if pw == nil {
			pw = []byte{}
		}
		return pw, nil
	case Unavailable:
		return nil, ErrNoProvider
	}
	return nil, ErrCancelled
}

// choice turns a Result into what Choose returns: a refusal, a timeout and a
// closed dialog all choose button 0.
func (r Result) choice(d Dialog) (int, error) {
	switch r.Outcome {
	case Answered:
		if r.Button >= 0 && r.Button < len(d.Buttons) {
			return r.Button, nil
		}
		return 0, nil
	case Unavailable:
		return 0, ErrNoProvider
	}
	return 0, nil
}
