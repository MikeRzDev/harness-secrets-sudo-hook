package guard

import (
	"regexp"
	"sort"
	"strings"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
)

// A harness reads a denied tool call as a stop, so the guard converts what it
// can instead: each place where sudo runs a command becomes psudo running the
// same command, and the call goes ahead. Only what it cannot convert exactly
// is denied, with the psudo form to use.
//
// It converts:
//
//	sudo [-n -E -H -k -u root -p …] [--] cmd …  →  psudo cmd …
//	… | sudo cmd … (psudo closes stdin)         →  psudo sh -c '… | cmd …'
//	ssh host sudo cmd …                         →  psudo -H host cmd …
//	timeout 5 sudo cmd …, xargs sudo cmd …      →  timeout 5 psudo cmd …
//
// The result is judged again; it is used only when the guard then allows it.

type edit struct {
	start, end int
	text       string
}

// plainWord is a word the shell passes on unchanged: no quotes, expansions
// or globs, so the remote shell of ssh reads it the same way.
var plainWord = regexp.MustCompile(`^[A-Za-z0-9_./:=@%+,-]+$`)

func (p *parser) plain(w word) bool {
	return !w.dynamic && !w.opaque && plainWord.MatchString(w.text) && p.src[w.start:w.end] == w.text
}

// isSudo reports whether w names the system's sudo. Another program called
// sudo (./tools/sudo) is not converted: psudo would not run what it runs.
func isSudo(w word) bool {
	switch w.text {
	case "sudo", "/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo", "/run/wrappers/bin/sudo",
		"/run/current-system/sw/bin/sudo":
		return !w.dynamic && !w.opaque
	}
	return false
}

func rootUser(v string) bool { return v == "root" || v == "0" || v == "#0" }

// sudoOptions returns the index of the program after sudo at k and its
// options, which psudo does not need: -n, -E, -H, -k, -u root, -p prompt.
// Any other option (another user, a login shell, -S reading a password from
// stdin) cannot be converted.
func sudoOptions(words []word, k int) (int, bool) {
	j := k + 1
	for j < len(words) {
		w := words[j]
		t := w.text
		if w.dynamic || w.opaque {
			return 0, false
		}
		switch {
		case t == "--":
			j++
			return j, j < len(words)
		case t == "-u" || t == "--user":
			if j+1 >= len(words) || !rootUser(words[j+1].text) {
				return 0, false
			}
			j += 2
		case t == "-p" || t == "--prompt":
			j += 2
		case strings.HasPrefix(t, "--user="):
			if !rootUser(strings.TrimPrefix(t, "--user=")) {
				return 0, false
			}
			j++
		case strings.HasPrefix(t, "--prompt=") || strings.HasPrefix(t, "--preserve-env="):
			j++
		case t == "--non-interactive" || t == "--preserve-env" || t == "--set-home" || t == "--reset-timestamp":
			j++
		case strings.HasPrefix(t, "--"):
			return 0, false
		case strings.HasPrefix(t, "-") && len(t) > 1:
			skip := 1
		cluster:
			for i := 1; i < len(t); i++ {
				switch t[i] {
				case 'n', 'E', 'H', 'k':
				case 'u', 'p':
					value := t[i+1:]
					if value == "" {
						if j+1 >= len(words) {
							return 0, false
						}
						value = words[j+1].text
						skip = 2
					}
					if t[i] == 'u' && !rootUser(value) {
						return 0, false
					}
					break cluster
				default:
					return 0, false
				}
			}
			j += skip
		default:
			return j, true
		}
	}
	return 0, false
}

// readsStdin reports whether cmd at index i of a pipeline gets input that
// psudo would not pass on: a pipe, a < redirection or a here-document.
func readsStdin(c *simpleCmd, i int) bool {
	return i > 0 || c.input || len(c.heredocs) > 0 || len(c.herestr) > 0
}

// Rewrite returns command with sudo converted to psudo, or false when some
// sudo in it cannot be converted exactly.
func Rewrite(command, self string) (string, bool) {
	if self == "" {
		return "", false
	}
	p := &parser{src: command, self: self}
	p.parse()
	if p.bad {
		return "", false
	}
	psudo := shquote.Quote(self)
	var edits []edit
	for _, pl := range p.pipes {
		var inside []edit // conversions inside this pipeline
		wrap := false
		for i, c := range pl.cmds {
			k := commandWord(c.words, 0)
			if k < 0 {
				continue
			}
			name := base(c.words[k].text)
			switch {
			case isSudo(c.words[k]):
				j, ok := sudoOptions(c.words, k)
				if !ok {
					return "", false
				}
				wrap = wrap || readsStdin(c, i)
				inside = append(inside, edit{c.words[k].start, c.words[j].start, ""})
			case name == "ssh" && !c.words[k].dynamic && k+3 < len(c.words) && isSudo(c.words[k+2]):
				host := c.words[k+1]
				if strings.HasPrefix(host.text, "-") || !p.plain(host) || readsStdin(c, i) {
					return "", false
				}
				j, ok := sudoOptions(c.words, k+2)
				if !ok {
					return "", false
				}
				for _, w := range c.words[j:] {
					if !p.plain(w) {
						return "", false
					}
				}
				edits = append(edits, edit{c.words[k].start, c.words[j].start, psudo + " -H " + host.text + " "})
			case wrappers[name]:
				for n := k + 1; n < len(c.words); n++ {
					if isSudo(c.words[n]) {
						j, ok := sudoOptions(c.words, n)
						if !ok {
							return "", false
						}
						edits = append(edits, edit{c.words[n].start, c.words[j].start, psudo + " "})
						n = j - 1
					}
				}
			}
		}
		if len(inside) == 0 {
			continue
		}
		if !wrap {
			for _, e := range inside {
				e.text = psudo + " "
				edits = append(edits, e)
			}
			continue
		}
		// psudo closes the command's stdin, so the data it should read is
		// produced inside psudo: the whole pipeline runs under sh -c. That
		// moves expansions and ~ to root's shell, which changes them, so a
		// pipeline that has any is not converted.
		first, last := pl.cmds[0], pl.cmds[len(pl.cmds)-1]
		start, end := first.start, last.end
		for _, c := range pl.cmds {
			if len(c.heredocs) > 0 || len(c.herestr) > 0 {
				return "", false
			}
		}
		if commandWord(first.words, 0) != 0 || strings.ContainsAny(command[start:end], "$`~\n") {
			return "", false
		}
		var inner strings.Builder
		at := start
		for _, e := range inside {
			inner.WriteString(command[at:e.start])
			at = e.end
		}
		inner.WriteString(command[at:end])
		edits = append(edits, edit{start, end, psudo + " sh -c " + shquote.Quote(inner.String())})
	}
	if len(edits) == 0 {
		return "", false
	}
	sort.Slice(edits, func(a, b int) bool { return edits[a].start < edits[b].start })
	var out strings.Builder
	at := 0
	for _, e := range edits {
		if e.start < at {
			return "", false
		}
		out.WriteString(command[at:e.start])
		out.WriteString(e.text)
		at = e.end
	}
	out.WriteString(command[at:])
	converted := out.String()
	if judge(converted, self) != allow {
		return "", false
	}
	return converted, true
}
