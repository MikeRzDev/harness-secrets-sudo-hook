package prompt

import (
	"encoding/json"
	"io"
)

// ServeApp is psudo running as the psudo.app dialog helper (psudo --dialog):
// it reads one Dialog as JSON from stdin, draws it with AppKit and writes the
// Result as JSON to stdout. It decides nothing about the dialog; it only draws
// what the Dialog says. Exit 2 means nothing was shown, and the caller then
// shows the same Dialog with osascript.
func ServeApp(in io.Reader, out io.Writer) int {
	if !TestApp {
		return 2 // a normal build has no app
	}
	var d Dialog
	if json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&d) != nil || d.check() != nil {
		return 2
	}
	r := render(d)
	if r.Outcome == Unavailable {
		return 2
	}
	if json.NewEncoder(out).Encode(r) != nil {
		return 2
	}
	return 0
}
