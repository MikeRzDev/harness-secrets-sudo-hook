package guard

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// The guard reads a Bash command the way the shell would, closely enough to
// tell where sudo or sshpass would actually run from where the word is only
// data (a heredoc written to a file, a commit message, a grep pattern). It is
// best effort, like the spec says: anything it cannot parse falls back to the
// plain word match, so a parse failure denies rather than allows.

// verdict is what a command does that the guard cares about.
type verdict int

const (
	allow verdict = iota
	// denyDynamic is a program name the guard cannot read ($cmd, ${x}),
	// with nothing else in the command that runs sudo. It is denied like
	// sudo, but with its own reason: the fix is to write the name out, and
	// the sudo reason made models believe the command itself was forbidden.
	denyDynamic
	denyRoot
	denyCache
)

func worse(a, b verdict) verdict {
	if b > a {
		return b
	}
	return a
}

// word is one shell word after quote removal. Expansions stay in the text as
// written ($x, $(…)), and dynamic records that one was present.
type word struct {
	text       string
	dynamic    bool
	opaque     bool // contains $'…', whose text cannot be judged
	start, end int  // its place in the source
	// split is an expansion outside double quotes: bash splits its value
	// into several words, so it can supply a program and its arguments.
	split bool
	// glob is an unquoted *, ? or [: the shell replaces the word with the
	// names of matching files, so /usr/bin/su?o runs sudo.
	glob bool
	// alts are the words an unquoted brace expansion makes of this one
	// (s{u,}do is sudo sdo), when it has one.
	alts []string
}

type heredoc struct {
	body    string
	literal bool // quoted delimiter: no expansions in the body
}

type simpleCmd struct {
	words    []word
	heredocs []*heredoc
	herestr  []string
	procsub  []string // the code of each <(…) and >(…)
	input    bool     // a < redirection: the program reads stdin
	// pattern marks a command that ends at ")": in case x in *.md|*) …,
	// the words before ")" are patterns, not programs.
	pattern    bool
	scope      *scope
	start, end int // its place in the source, redirections included
}

type pipeline struct{ cmds []*simpleCmd }

// scope holds the values this command assigns to variables, as written:
// CMD='qm list' lets ssh host "$CMD" be judged by what it runs. A variable
// that is ever given a computed value is unknown.
//
// Only plain assignments are modelled, and the guard fails closed: a
// variable is known only when its name appears in the command as those
// assignments and as exact $NAME or ${NAME} reads, nowhere else (read NAME,
// for NAME in, getopts, let, (( )) set it too); when it is not a name the
// shell sets itself (REPLY, OPTARG, $_ …); and when the command has nothing
// that can set a variable without naming it (settersWord: read, printf,
// eval, source …, or an expansion such as ${(P)n::=v} or ${!n}).
type scope struct {
	src     string // the whole command, to find every mention of a name
	lits    map[string][]string
	unknown map[string]bool
}

// mentions counts the places src names the variable name other than as an
// exact $NAME or ${NAME} read.
func mentions(src, name string) int {
	n := 0
	for _, m := range identifier.FindAllStringIndex(src, -1) {
		if src[m[0]:m[1]] != name {
			continue
		}
		before := byte(0)
		if m[0] > 0 {
			before = src[m[0]-1]
		}
		if before == '$' {
			continue
		}
		if before == '{' && m[0] > 1 && src[m[0]-2] == '$' && m[1] < len(src) && src[m[1]] == '}' {
			continue
		}
		n++
	}
	return n
}

var identifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// literal returns the values a word that is exactly $NAME or ${NAME},
// expanded here, can have: those assigned to NAME in this command. It
// returns nil for any other word and for a variable that is unknown.
func (sc *scope) literal(w word) []string {
	name := sc.varOf(w)
	if name == "" || sc.unknown[name] {
		return nil
	}
	// Each literal assignment is one mention; any other one may set it.
	if mentions(sc.src, name) != len(sc.lits[name]) || shellSets(name) || setsUnnamed(sc.src) {
		return nil
	}
	return sc.lits[name]
}

// varOf returns NAME for a word that is exactly $NAME or ${NAME}, or "".
func (sc *scope) varOf(w word) string {
	if sc == nil || !w.dynamic || w.opaque {
		return ""
	}
	name := strings.TrimPrefix(w.text, "$")
	if strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}") {
		name = name[1 : len(name)-1]
	}
	if name == w.text || varName.FindString(name) != name {
		return ""
	}
	return name
}

// candidates returns the literal values assigned to the variable of w in
// this command, also when literal does not follow it. Judging them as well
// can only add a refusal: a command that assigns a value with the root
// command and then reads the variable is refused even when the variable is
// not followed.
func (sc *scope) candidates(w word) []string {
	if name := sc.varOf(w); name != "" {
		return sc.lits[name]
	}
	return nil
}

// builtins are the builtins of bash (5) and zsh (5.9, with the modules a
// startup file may load). Only a builtin can set a variable of the shell it
// runs in, or run code there; a program it starts cannot.
var builtins = words(`. : [ alias autoload bg bind bindkey break builtin bye caller cd chdir command
	compadd comparguments compcall compctl compdescribe compfiles compgen complete compgroups compopt
	compquote compset comptags comptry compvalues continue coproc declare dirs disable disown echo echotc
	echoti emulate enable eval exec exit export false fc fg float functions getln getopts hash help history
	integer jobs kill let limit local log logout mapfile noglob nocorrect popd print printf private pushd
	pushln pwd r read readarray readonly rehash return sched select set setopt shift shopt source suspend
	test times trap true ttyctl type typeset ulimit umask unalias unfunction unhash unlimit unset unsetopt
	vared wait whence where which zcompile zformat zle zmodload zparseopts zregexparse zstyle
	strftime sysread syswrite zstat stat zselect zsocket ztcp zpty zsystem zgetattr zsetattr zdelattr
	zlistattr zftp zprof zcurses zgdbmpath ztie zuntie pcre_compile pcre_match pcre_study regex zsh`)

// quietBuiltins set no variable but the ones shellSets lists (cd sets PWD)
// and run no code.
var quietBuiltins = words(`: [ test true false echo pwd cd chdir pushd popd dirs exit return break
	continue shift kill jobs bg fg disown suspend times type whence where which umask ulimit limit
	unlimit help logout bye echotc echoti ttyctl`)

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// setsUnnamed reports whether src may set a variable whose name it does not
// write out: any word that is a builtin other than a quiet one (found
// anywhere, also inside quotes: a false alarm only means the variable is not
// followed), the . builtin, or an expansion that assigns or names a
// variable indirectly.
func setsUnnamed(src string) bool {
	for _, m := range identifier.FindAllString(src, -1) {
		if builtins[m] && !quietBuiltins[m] {
			return true
		}
	}
	return dotCommand.MatchString(src) || strings.Contains(src, "${!") || strings.Contains(src, "(P)") ||
		strings.Contains(src, ":=") || strings.Contains(src, "::=") || strings.Contains(src, "((")
}

// dotCommand is the . builtin (source) as a command word.
var dotCommand = regexp.MustCompile(`(^|[\s;&|(){}!])\.(\s|$)`)

// shellSets reports whether the shell itself sets name (bash or zsh): its
// value then need not come from an assignment in the command.
func shellSets(name string) bool {
	if strings.HasPrefix(name, "BASH") || strings.HasPrefix(name, "ZSH") || strings.HasPrefix(name, "COMP_") {
		return true
	}
	switch name {
	case "_", "REPLY", "reply", "OPTARG", "OPTIND", "OPTERR", "MAPFILE", "PWD", "OLDPWD", "RANDOM",
		"SRANDOM", "SECONDS", "LINENO", "PIPESTATUS", "pipestatus", "status", "HISTCMD", "EPOCHREALTIME",
		"EPOCHSECONDS", "COPROC", "match", "MATCH", "mbegin", "mend", "MBEGIN", "MEND", "argv", "ERRNO",
		"PATH", "path", "FPATH", "fpath", "CDPATH", "cdpath", "MANPATH", "manpath", "IFS", "UID", "EUID",
		"PPID", "SHLVL", "HOME", "USER", "LOGNAME", "SHELL", "TTY", "PS4", "PROMPT_COMMAND", "TRY_BLOCK_ERROR",
		"DIRSTACK", "dirstack", "COLUMNS", "LINES", "HISTFILE", "OPTERRNO", "aliases", "commands", "functions",
		"parameters", "options", "history", "jobtexts", "mapfile", "nameddirs", "userdirs", "termcap", "terminfo":
		return true
	}
	return false
}

// record notes the assignment w, which is literal unless w is dynamic.
func (sc *scope) record(w word) {
	name, value, ok := strings.Cut(w.text, "=")
	name = strings.TrimSuffix(name, "+")
	if !ok || varName.FindString(name) != name {
		return
	}
	if w.dynamic || w.opaque || strings.HasSuffix(w.text[:len(name)+1], "+") {
		sc.unknown[name] = true
		return
	}
	sc.lits[name] = append(sc.lits[name], value)
}

type pendingDoc struct {
	cmd   *simpleCmd
	delim string
	strip bool // <<-
	lit   bool
}

type parser struct {
	src     string
	i       int
	depth   int
	self    string
	bad     bool
	nested  verdict // from command substitutions
	pipes   []*pipeline
	pipe    *pipeline
	cmd     *simpleCmd
	scope   *scope
	pending []pendingDoc
	tok     int // where the current token starts
}

const maxDepth = 16

var (
	cacheTools = map[string]bool{"security": true, "secret-tool": true}
	// Programs whose arguments, here-docs or stdin are shell code.
	carriers = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true,
		"fish": true, "ssh": true, "eval": true, "su": true, "source": true, ".": true, "trap": true}
	// Shells: the code they are given is parsed and judged like the command
	// itself, not only matched as text.
	shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true,
		"fish": true}
	unquoted = strings.NewReplacer(`\`, "", `'`, "", `"`, "")
	// Variables a shell expands as code when it shows them (bash -x prints
	// PS4, with its $(…) run).
	promptVars = map[string]bool{"PS1": true, "PS2": true, "PS3": true, "PS4": true, "PROMPT_COMMAND": true}
	// Programs that run another program given as a later argument.
	wrappers = map[string]bool{"env": true, "nohup": true, "time": true, "exec": true, "command": true,
		"builtin": true, "nice": true, "ionice": true, "xargs": true, "timeout": true, "stdbuf": true,
		"caffeinate": true, "watch": true, "chrt": true, "taskset": true, "unbuffer": true, "doas": true,
		"find": true, "setsid": true, "flock": true, "parallel": true, "script": true, "runuser": true,
		"chroot": true, "nsenter": true, "unshare": true, "systemd-run": true, "sg": true, "strace": true,
		"ltrace": true, "arch": true, "nohup.exe": true}
	// Interpreters: their arguments, here-docs and stdin are code too.
	interpreter = regexp.MustCompile(`^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|deno|bun|php[0-9.]*|` +
		`[gmn]?awk|osascript|expect|tclsh|wish|lua[0-9.]*|Rscript|pwsh|swift|groovy|jshell|irb)$`)
	// Programs that only read or write data. For these alone, the word "sudo"
	// in an argument or here-document is text. Every other program is judged
	// on its full text, so an unknown program fails closed.
	dataCommands = map[string]bool{"cat": true, "tee": true, "echo": true, "printf": true, "grep": true,
		"egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true, "git": true, "gh": true, "ls": true,
		"head": true, "tail": true, "wc": true, "diff": true, "cmp": true, "less": true, "more": true,
		"mkdir": true, "cp": true, "mv": true, "rm": true, "touch": true, "ln": true, "chmod": true, "jq": true,
		"yq": true, "sort": true, "uniq": true, "cut": true, "tr": true, "column": true, "test": true, "[": true,
		"true": true, "false": true, "stat": true, "file": true, "basename": true, "dirname": true,
		"realpath": true, "readlink": true, "pwd": true, "cd": true, "man": true, "which": true, "type": true,
		// Loop and case words: a list of words, not a program.
		"for": true, "select": true, "case": true}
	reserved = map[string]bool{"!": true, "{": true, "}": true, "if": true, "then": true, "else": true,
		"elif": true, "fi": true, "do": true, "done": true, "while": true, "until": true, "function": true}
	assignment   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=`)
	cachePattern = regexp.MustCompile(`harness-root-hook`)
	cacheToolPat = regexp.MustCompile(`(^|[^A-Za-z0-9_-])(security|secret-tool)([^A-Za-z0-9_-]|$)`)
	// Reads that print a secret from any credential-store entry, which could
	// be one of psudo's stored secrets (docs/secrets.md §7.1).
	// security -i reads its commands from stdin, so what it does is not in
	// its arguments: it counts as a read.
	credReadPat = regexp.MustCompile(`find-(generic|internet)-password[^;&|\n]*\s-[A-Za-z]*[wg]|` +
		`dump-keychain[^;&|\n]*\s-[A-Za-z]*d|secret-tool\s+(lookup|search)|` +
		`security(\s+-[hlqv]+|\s+-p\s*\S+)*\s+-[hlqv]*i[hilqv]*([^A-Za-z0-9_-]|$)`)
	flagCluster = regexp.MustCompile(`^-[A-Za-z]+$`)
	// security's own options (-h -i -l -q -v) in a cluster that has -i.
	interactive = regexp.MustCompile(`^-[hlqv]*i[hilqv]*$`)
	caseWord    = regexp.MustCompile(`(^|[^A-Za-z0-9_])case([^A-Za-z0-9_]|$)`)
)

// ownName is this project's name. It holds the word sudo between dashes, and
// every path into a checkout and every link to the repository holds the name
// (cd …/harness-secrets-sudo-hook, git clone, go install). Read as text it
// would deny all of those, so the plain-text rule skips exactly this name. It
// is swapped for a single letter, so whatever stands next to it is judged as
// before. A command word called sudo is denied wherever it lives, also inside
// a folder of this name.
const ownName = "harness-secrets-sudo-hook"

// textVerdict is the plain-text rule, used for code the guard does not parse
// (an argument of sh -c or ssh) and as the fail-closed fallback.
//
// Text often reaches a shell later (sh -c, ssh, a git alias, a pager
// variable), which removes quotes and backslashes first: s\udo and s”udo
// run sudo. So the text is matched once more without them.
func textVerdict(s string) verdict {
	v := allow
	s = strings.ReplaceAll(s, ownName, "x")
	if pattern.MatchString(s) || pattern.MatchString(unquoted.Replace(s)) {
		v = denyRoot
	}
	if cacheToolPat.MatchString(s) && (cachePattern.MatchString(s) || credReadPat.MatchString(s)) {
		v = worse(v, denyCache)
	}
	return v
}

// credentialRead reports whether security or secret-tool with args would
// read psudo's entries or print a secret from any entry. An argument the
// guard cannot judge ($x) counts as a read.
func credentialRead(tool string, args []word) bool { return storeRead(tool, args, true) }

// storeRead is credentialRead. With strict false, an argument the guard cannot
// judge does not count: that is for a word that may be the program or only an
// argument (grep security "$file"), where denying would refuse ordinary work.
func storeRead(tool string, args []word, strict bool) bool {
	sub := ""
	for _, w := range args {
		if strict && (w.dynamic || w.opaque) || cachePattern.MatchString(w.text) {
			return true
		}
		if sub == "" && !strings.HasPrefix(w.text, "-") {
			sub = w.text
		}
	}
	if tool == "secret-tool" {
		return sub == "lookup" || sub == "search"
	}
	// security -i (before any subcommand) reads its commands from stdin,
	// where the guard cannot see them. -p takes a value.
	for i := 0; i < len(args) && strings.HasPrefix(args[i].text, "-"); i++ {
		if interactive.MatchString(args[i].text) {
			return true
		}
		if args[i].text == "-p" {
			i++
		}
	}
	flags := ""
	for _, w := range args {
		if flagCluster.MatchString(w.text) {
			flags += w.text[1:]
		}
	}
	switch sub {
	case "find-generic-password", "find-internet-password":
		return strings.ContainsAny(flags, "wg")
	case "dump-keychain":
		return strings.Contains(flags, "d")
	}
	return false
}

// readsStore reports whether words, the arguments of a wrapper, contain a
// credential-store read: security or secret-tool anywhere among them with
// arguments that read. The program a wrapper runs may come after a value
// (timeout 5 security …, find . -exec security …), so every position counts.
func readsStore(words []word) bool {
	for i, w := range words {
		if name := base(w.text); cacheTools[name] && storeRead(name, words[i+1:], false) {
			return true
		}
	}
	return false
}

// psudoCommand returns the command psudo is asked to run: its arguments
// after -H <host>, --secret and --secret-file options and "--".
func psudoCommand(args []word) []word {
	for i := 0; i < len(args); {
		switch t := args[i].text; {
		case t == "-H" || t == "--secret" || t == "--secret-file":
			i += 2
		case strings.HasPrefix(t, "--secret=") || strings.HasPrefix(t, "--secret-file="):
			i++
		case t == "--":
			return args[i+1:]
		default:
			return args[i:]
		}
	}
	return nil
}

// judge reports what a Bash command would do that psudo's guard denies.
// self is the installed psudo; only that binary's arguments are trusted.
func judge(command, self string) verdict { return decideDepth(command, 0, self) }

func decideDepth(command string, depth int, self string) verdict {
	if depth > maxDepth {
		return textVerdict(command)
	}
	p := &parser{src: command, depth: depth, self: self}
	p.parse()
	p.collect()
	if p.bad {
		// Text the guard cannot parse is matched as text. With an expansion
		// in it, that text could spell any program, so it is denied.
		v := textVerdict(command)
		if strings.ContainsAny(command, "$`") {
			v = worse(v, denyDynamic)
		}
		return v
	}
	v := p.nested
	for _, pl := range p.pipes {
		v = worse(v, pl.verdict(command, self, depth))
	}
	return v
}

// code judges text that a shell will run later (the code of sh -c, eval or
// ssh) by parsing it, like the command itself. judged says the guard already
// parsed the substitutions in it (they were not in single quotes): text that
// is then a single command substitution, eval "$(brew shellenv)", needs no
// more; what it prints is data the guard cannot see, as with cmd | sh.
func code(text string, judged bool, depth int, self string) verdict {
	t := strings.TrimSpace(text)
	if !judged {
		return decideDepth(text, depth+1, self)
	}
	if strings.HasPrefix(t, "$(") && !strings.HasPrefix(t, "$((") {
		if end, ok := matchParen(t, 2); ok && end == len(t)-1 {
			return allow
		}
	}
	if len(t) > 1 && t[0] == '`' && strings.IndexByte(t[1:], '`') == len(t)-2 {
		return allow
	}
	return decideDepth(text, depth+1, self)
}

func (p *parser) eof() bool { return p.i >= len(p.src) }

func (p *parser) endCmd() {
	if p.cmd != nil && (len(p.cmd.words) > 0 || len(p.cmd.heredocs) > 0 || len(p.cmd.herestr) > 0) {
		if p.pipe == nil {
			p.pipe = &pipeline{}
		}
		p.pipe.cmds = append(p.pipe.cmds, p.cmd)
	}
	p.cmd = nil
}

func (p *parser) endPipe() {
	p.endCmd()
	if p.pipe != nil {
		p.pipes = append(p.pipes, p.pipe)
	}
	p.pipe = nil
}

func (p *parser) current() *simpleCmd {
	if p.cmd == nil {
		if p.scope == nil {
			p.scope = &scope{src: p.src, lits: map[string][]string{}, unknown: map[string]bool{}}
		}
		p.cmd = &simpleCmd{start: p.tok, scope: p.scope}
	}
	return p.cmd
}

// collect records the assignments of every command: before its program
// (A=1 cmd), alone (A=1), and as the arguments of export, local, declare,
// typeset and readonly.
func (p *parser) collect() {
	for _, pl := range p.pipes {
		for _, c := range pl.cmds {
			k := commandWord(c.words, 0)
			end := k
			if k < 0 {
				end = len(c.words)
			}
			for _, w := range c.words[:end] {
				if assignment.MatchString(w.text) {
					c.scope.record(w)
				}
			}
			if k >= 0 {
				switch c.words[k].text {
				case "export", "local", "declare", "typeset", "readonly":
					// An option changes what the assignment does (-n makes
					// a reference, -i evaluates the value): its names are
					// unknown.
					opts := slices.ContainsFunc(c.words[k+1:], func(w word) bool {
						return strings.HasPrefix(w.text, "-") || strings.HasPrefix(w.text, "+")
					})
					for _, w := range c.words[k+1:] {
						if !assignment.MatchString(w.text) {
							continue
						}
						if opts || w.dynamic {
							name, _, _ := strings.Cut(w.text, "=")
							c.scope.unknown[strings.TrimSuffix(name, "+")] = true
							continue
						}
						c.scope.record(w)
					}
				}
			}
		}
	}
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

func isOp(c byte) bool { return strings.IndexByte(";&|()<>", c) >= 0 }

func (p *parser) parse() {
	atWordStart := true
	for !p.eof() && !p.bad {
		c := p.src[p.i]
		p.tok = p.i
		switch {
		case isBlank(c):
			p.i++
			atWordStart = true
			continue
		case c == '\\' && p.i+1 < len(p.src) && p.src[p.i+1] == '\n':
			p.i += 2
			continue
		case c == '#' && atWordStart:
			for !p.eof() && p.src[p.i] != '\n' {
				p.i++
			}
			continue
		case c == '\n':
			p.i++
			p.endPipe()
			p.readHeredocs()
		case c == '|':
			p.i++
			if !p.eof() && p.src[p.i] == '|' {
				p.i++
				p.endPipe()
			} else {
				if !p.eof() && p.src[p.i] == '&' {
					p.i++
				}
				p.endCmd()
			}
		case c == '&' && p.i+1 < len(p.src) && p.src[p.i+1] == '>':
			p.i += 2
			if !p.eof() && p.src[p.i] == '>' {
				p.i++
			}
			p.redirectTarget()
		case c == ';' || c == '&' || c == '(' || c == ')':
			if c == ')' {
				p.endCmd()
				if p.pipe != nil {
					for _, pc := range p.pipe.cmds {
						pc.pattern = true
					}
				}
			}
			p.i++
			for !p.eof() && (p.src[p.i] == ';' || p.src[p.i] == '&') && (c == ';' || c == '&') {
				p.i++
			}
			p.endPipe()
		case c == '<' || c == '>':
			p.redirect()
		case c >= '0' && c <= '9' && p.fdRedirect():
			// digits were part of a redirection such as 2>/dev/null
		default:
			w := p.word()
			if p.bad {
				return
			}
			cmd := p.current()
			cmd.words = append(cmd.words, w)
		}
		if p.cmd != nil {
			p.cmd.end = p.i
		}
		atWordStart = true
	}
	if p.bad {
		return
	}
	p.endPipe()
	if len(p.pending) > 0 {
		p.bad = true // here-document never started
	}
}

// fdRedirect consumes "N>" or "N<" when the digits run straight into it.
func (p *parser) fdRedirect() bool {
	j := p.i
	for j < len(p.src) && p.src[j] >= '0' && p.src[j] <= '9' {
		j++
	}
	if j < len(p.src) && (p.src[j] == '<' || p.src[j] == '>') {
		p.i = j
		p.redirect()
		return true
	}
	return false
}

func (p *parser) redirect() {
	start := p.i
	for !p.eof() && strings.IndexByte("<>&|-", p.src[p.i]) >= 0 && p.i-start < 3 {
		if p.src[p.i] == '-' && !strings.HasPrefix(p.src[start:], "<<") {
			break
		}
		p.i++
	}
	op := p.src[start:p.i]
	if (op == "<" || op == ">") && !p.eof() && p.src[p.i] == '(' {
		// Process substitution: its code runs, and a shell given <(…)
		// runs what that code prints.
		end, ok := matchParen(p.src, p.i+1)
		if !ok {
			p.bad = true
			return
		}
		inner := p.src[p.i+1 : end]
		p.current().procsub = append(p.current().procsub, inner)
		p.substitute(inner)
		p.i = end + 1
		return
	}
	if strings.HasPrefix(op, "<") && !strings.HasPrefix(op, "<<") {
		p.current().input = true
	}
	switch {
	case strings.HasPrefix(op, "<<<"):
		w := p.nextWord()
		cmd := p.current()
		cmd.herestr = append(cmd.herestr, w.text)
	case strings.HasPrefix(op, "<<"):
		p.skipBlanks()
		lit := false
		raw := p.i
		w := p.word()
		if strings.ContainsAny(p.src[raw:p.i], `'"\`) {
			lit = true
		}
		if w.text == "" {
			p.bad = true
			return
		}
		cmd := p.current()
		p.pending = append(p.pending, pendingDoc{cmd: cmd, delim: w.text, strip: op == "<<-", lit: lit})
	case strings.HasSuffix(op, "&"):
		p.redirectTarget() // >&2 or <&0: the target is a descriptor or a file
	default:
		p.redirectTarget()
	}
}

func (p *parser) skipBlanks() {
	for !p.eof() && isBlank(p.src[p.i]) {
		p.i++
	}
}

// redirectTarget reads the file word after a redirection. It is not an
// argument, but substitutions inside it still run.
func (p *parser) redirectTarget() { p.nextWord() }

func (p *parser) nextWord() word {
	p.skipBlanks()
	if p.eof() || isOp(p.src[p.i]) || p.src[p.i] == '\n' {
		return word{}
	}
	return p.word()
}

func (p *parser) readHeredocs() {
	for _, d := range p.pending {
		var body strings.Builder
		found := false
		for !p.eof() {
			end := strings.IndexByte(p.src[p.i:], '\n')
			line := ""
			if end < 0 {
				line, p.i = p.src[p.i:], len(p.src)
			} else {
				line, p.i = p.src[p.i:p.i+end], p.i+end+1
			}
			cmp := line
			if d.strip {
				cmp = strings.TrimLeft(line, "\t")
			}
			if cmp == d.delim {
				found = true
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if !found {
			p.bad = true
			return
		}
		doc := &heredoc{body: body.String(), literal: d.lit}
		d.cmd.heredocs = append(d.cmd.heredocs, doc)
		if !doc.literal {
			p.scanExpansions(doc.body)
		}
	}
	p.pending = nil
}

// scanExpansions checks command substitutions in text the shell expands but
// does not split into words (an unquoted here-document body).
func (p *parser) scanExpansions(s string) {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i++
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
			end, ok := matchParen(s, i+2)
			if !ok {
				p.bad = true
				return
			}
			p.substitute(s[i+2 : end])
			i = end
		case s[i] == '`':
			end := strings.IndexByte(s[i+1:], '`')
			if end < 0 {
				p.bad = true
				return
			}
			p.substitute(strings.ReplaceAll(s[i+1:i+1+end], "\\`", "`"))
			i += end + 1
		}
	}
}

func (p *parser) substitute(code string) {
	p.nested = worse(p.nested, decideDepth(code, p.depth+1, p.self))
}

// matchParen returns the index of the ")" closing a "(" just before start.
func matchParen(s string, start int) (int, bool) {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return 0, false
			}
			i += end + 1
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
			if i >= len(s) {
				return 0, false
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// matchBrace returns the index of the "}" closing a "${" just before start,
// or -1. unsure reports quotes, escapes or substitutions on the way, where
// bash and zsh may end the ${…} elsewhere. Inside double quotes a single
// quote is an ordinary character.
func matchBrace(s string, start int, inDQ bool) (end int, unsure bool) {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '\\':
			unsure = true
			i++
		case '\'':
			if inDQ {
				continue
			}
			unsure = true
			n := strings.IndexByte(s[i+1:], '\'')
			if n < 0 {
				return -1, true
			}
			i += n + 1
		case '"':
			unsure = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
			if i >= len(s) {
				return -1, true
			}
		case '`':
			unsure = true
			n := strings.IndexByte(s[i+1:], '`')
			if n < 0 {
				return -1, true
			}
			i += n + 1
		case '$':
			if i+1 < len(s) && s[i+1] == '(' {
				unsure = true
				n, ok := matchParen(s, i+2)
				if !ok {
					return -1, true
				}
				i = n
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, unsure
			}
		}
	}
	return -1, unsure
}

// word reads one word, removing quotes and checking substitutions.
func (p *parser) word() (w word) {
	var b strings.Builder
	// bare marks each byte of the text that was not quoted: only those can
	// be glob or brace syntax.
	var bare []bool
	pad := func() {
		for len(bare) < b.Len() {
			bare = append(bare, false)
		}
	}
	w = word{start: p.i}
	defer func() { w.end = p.i }() // a named result, so every return carries it
	for !p.eof() {
		c := p.src[p.i]
		if isBlank(c) || c == '\n' || isOp(c) {
			break
		}
		switch c {
		case '\'':
			end := strings.IndexByte(p.src[p.i+1:], '\'')
			if end < 0 {
				p.bad = true
				return w
			}
			b.WriteString(p.src[p.i+1 : p.i+1+end])
			p.i += end + 2
		case '"':
			p.i++
			for !p.eof() && p.src[p.i] != '"' {
				d := p.src[p.i]
				switch {
				case d == '\\' && p.i+1 < len(p.src) && strings.IndexByte("$`\"\\\n", p.src[p.i+1]) >= 0:
					if p.src[p.i+1] != '\n' {
						b.WriteByte(p.src[p.i+1])
					}
					p.i += 2
				case d == '$' || d == '`':
					p.expansion(&b, &w, true)
				default:
					b.WriteByte(d)
					p.i++
				}
				if p.bad {
					return w
				}
			}
			if p.eof() {
				p.bad = true
				return w
			}
			p.i++
		case '\\':
			if p.i+1 < len(p.src) {
				if p.src[p.i+1] != '\n' {
					b.WriteByte(p.src[p.i+1])
				}
				p.i += 2
			} else {
				p.i++
			}
		case '$', '`':
			if c == '`' || p.i+1 < len(p.src) && p.src[p.i+1] != '\'' {
				w.split = true
			}
			p.expansion(&b, &w, false)
		default:
			pad()
			b.WriteByte(c)
			bare = append(bare, true)
			p.i++
		}
		pad()
		if p.bad {
			return w
		}
	}
	w.text = b.String()
	pad()
	w.glob = isGlob(w.text, bare)
	if alts := braces(w.text, bare, 64); len(alts) > 1 {
		w.alts = alts
	}
	return w
}

// isGlob reports whether s, where bare marks the bytes that were not quoted,
// is a file name pattern: an unquoted * or ?, or an unquoted [ with an
// unquoted ] after it. A lone [ is the test command, not a pattern.
func isGlob(s string, bare []bool) bool {
	open := false
	for i := 0; i < len(s); i++ {
		if !bare[i] {
			continue
		}
		switch s[i] {
		case '*', '?':
			return true
		case '[':
			open = true
		case ']':
			if open {
				return true
			}
		}
	}
	return false
}

// braces returns the words brace expansion makes of s, where bare marks the
// bytes that were not quoted: {a,b} and {1..3}, nested too. At most limit
// words are made; a word without an expansion is returned as it is.
func braces(s string, bare []bool, limit int) []string {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' || !bare[i] {
			continue
		}
		depth := 0
		// parts are the [from, to) ranges of the alternatives.
		var parts [][2]int
		from, dots := i+1, -1
		for j := i; j < len(s); j++ {
			if !bare[j] {
				continue
			}
			switch {
			case s[j] == '{':
				depth++
			case s[j] == '}':
				depth--
			case s[j] == ',' && depth == 1:
				parts = append(parts, [2]int{from, j})
				from = j + 1
			case s[j] == '.' && depth == 1 && dots < 0 && j+1 < len(s) && s[j+1] == '.':
				dots = j
			}
			if depth > 0 {
				continue
			}
			switch {
			case len(parts) > 0:
				parts = append(parts, [2]int{from, j})
			case dots >= 0:
				// {a..b}: its end points are enough to judge the words.
				parts = [][2]int{{i + 1, dots}, {dots + 2, j}}
			default:
				parts = nil // {x} is not an expansion
			}
			if parts == nil {
				break
			}
			var out []string
			for _, r := range parts {
				if len(out) >= limit {
					break
				}
				part := s[:i] + s[r[0]:r[1]] + s[j+1:]
				mask := append(append(append([]bool(nil), bare[:i]...), bare[r[0]:r[1]]...), bare[j+1:]...)
				out = append(out, braces(part, mask, limit-len(out))...)
			}
			return out
		}
	}
	return []string{s}
}

// expansion consumes $…, ${…}, $(…), $((…)) or `…` at p.i.
func (p *parser) expansion(b *strings.Builder, w *word, inDQ bool) {
	w.dynamic = true
	s := p.src
	if s[p.i] == '`' {
		end := strings.IndexByte(s[p.i+1:], '`')
		for end >= 0 && s[p.i+end] == '\\' { // an escaped backtick inside
			next := strings.IndexByte(s[p.i+end+2:], '`')
			if next < 0 {
				end = -1
				break
			}
			end += next + 1
		}
		if end < 0 {
			p.bad = true
			return
		}
		p.substitute(strings.ReplaceAll(s[p.i+1:p.i+1+end], "\\`", "`"))
		b.WriteString(s[p.i : p.i+end+2])
		p.i += end + 2
		return
	}
	if p.i+1 >= len(s) {
		b.WriteByte('$')
		p.i++
		return
	}
	switch s[p.i+1] {
	case '(':
		end, ok := matchParen(s, p.i+2)
		if !ok {
			p.bad = true
			return
		}
		if strings.HasPrefix(s[p.i:], "$((") {
			// Arithmetic: not a command, but $(…) inside it still runs.
			p.scanExpansions(s[p.i+2 : end])
		} else {
			inner := s[p.i+2 : end]
			if caseWord.MatchString(inner) {
				// case patterns end in ")", which this matcher cannot pair
				// reliably: deny rather than misread where the code ends.
				p.nested = worse(p.nested, denyRoot)
			}
			p.substitute(inner)
		}
		b.WriteString(s[p.i : end+1])
		p.i = end + 1
	case '{':
		// bash and zsh do not agree where ${…} ends when a } sits in quotes
		// or in $(…) inside it ("${x:-'}'}", ${x:-$(echo })}). Code could
		// hide behind either reading, so a ${…} whose end depends on it is
		// not parsed. Nested ${…} alone end the same in both.
		first := strings.IndexByte(s[p.i:], '}')
		closing, unsure := matchBrace(s, p.i+2, inDQ)
		if first < 0 || closing < 0 || unsure && closing != p.i+first {
			p.bad = true
			return
		}
		end := closing - p.i
		body := s[p.i+2 : p.i+end]
		// zsh's (e) flag and bash's @P run the command substitutions in the
		// variable's value, which the guard cannot see.
		if flags, _, ok := strings.Cut(strings.TrimPrefix(body, "("), ")"); ok && strings.HasPrefix(body, "(") &&
			strings.ContainsRune(flags, 'e') || strings.HasSuffix(body, "@P") {
			p.nested = worse(p.nested, denyDynamic)
		}
		// ${x:-$(…)} and similar run their command substitutions.
		p.scanExpansions(body)
		b.WriteString(s[p.i : p.i+end+1])
		p.i += end + 1
	case '\'':
		// $'…' (ANSI-C quoting) can spell any word in escapes, so its
		// content cannot be judged as text.
		w.opaque = true
		j := p.i + 2
		for j < len(s) && s[j] != '\'' {
			if s[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(s) {
			p.bad = true
			return
		}
		b.WriteString(s[p.i : j+1])
		p.i = j + 1
	default:
		b.WriteByte('$')
		p.i++
	}
}

func base(s string) string { return path.Base(s) }

// programName is a plain file name: what a path must end in for the guard
// to know the program when only its folder is computed.
var programName = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// literalProgram reports whether a computed program word, as written in the
// source (raw, quotes included), names its program literally with only the
// folder computed: "$h"/fleet-ssh, "${HOME}"/bin/tool.
//
// Every expansion must be inside double quotes. Unquoted, the shell splits
// and globs its value, so $h/fleet-ssh with h='sudo id; ' runs sudo. Only
// $name and ${…} holding plain text are accepted: $(…), backticks and nested
// expansions are refused rather than parsed. The last / must follow every
// expansion, so "${p:-/bin/sh}" (which runs $p) does not count.
func literalProgram(raw string) bool {
	i := strings.LastIndexByte(raw, '/')
	if i < 0 || !programName.MatchString(raw[i+1:]) {
		return false
	}
	s := raw[:i]
	inDQ := false
	for k := 0; k < len(s); k++ {
		switch s[k] {
		case '\\':
			k++
		case '\'':
			if !inDQ {
				end := strings.IndexByte(s[k+1:], '\'')
				if end < 0 {
					return false
				}
				k += end + 1
			}
		case '"':
			inDQ = !inDQ
		case '`', '[', ']', '(', ')':
			// Subscripts, globs and substitutions, quoted or not: bash and
			// zsh read them differently, so none is parsed.
			return false
		case '*', '?':
			if !inDQ {
				return false
			}
		case '$':
			if !inDQ {
				return false
			}
			// Only ${name} and $name, whose meaning is the same in bash and
			// zsh. ${x@P} runs the $(…) in x's value, ${!x} reads another
			// variable, and zsh reads "$x[1]" and "$x:h" as a subscript and
			// a modifier, so every operator is refused.
			if strings.HasPrefix(s[k+1:], "{") {
				end := strings.IndexByte(s[k+2:], '}')
				if body := s[k+2 : k+2+max(end, 0)]; end <= 0 || varName.FindString(body) != body {
					return false
				}
				k += end + 2
				continue
			}
			n := len(varName.FindString(s[k+1:]))
			if n == 0 {
				return false
			}
			k += n
			if k+1 < len(s) && s[k+1] != '"' && s[k+1] != '/' {
				return false
			}
		}
	}
	return !inDQ
}

// varName is a shell variable name, used whole inside ${…} and as the prefix
// of $name.
var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// commandWord returns the index of the program a simple command runs,
// skipping assignments and reserved words, or -1.
func commandWord(words []word, from int) int {
	for k := from; k < len(words); k++ {
		t := words[k].text
		if reserved[t] || assignment.MatchString(t) {
			continue
		}
		return k
	}
	return -1
}

func (pl *pipeline) verdict(full, self string, depth int) verdict {
	v := allow
	carrierInPipe, shellInPipe, localShell := false, false, false
	for _, c := range pl.cmds {
		cv, carrier := c.verdict(full, self, depth)
		v = worse(v, cv)
		carrierInPipe = carrierInPipe || carrier
		if sh, local := c.runsShell(self, depth); sh {
			shellInPipe, localShell = true, localShell || local
		}
	}
	if carrierInPipe {
		// Data piped into a shell or ssh is code.
		for _, c := range pl.cmds {
			v = worse(v, c.textVerdict())
		}
	}
	if shellInPipe {
		for _, c := range pl.cmds {
			if pv := c.printed(depth, self); localShell {
				v = worse(v, pv)
			} else {
				v = worse(v, remote(pv))
			}
		}
	}
	return v
}

// printed judges what c prints, as code for a shell that reads it: the
// arguments of echo and printf, and here-documents (cat <<'EOF' | sh).
func (c *simpleCmd) printed(depth int, self string) verdict {
	v := allow
	if k := commandWord(c.words, 0); k >= 0 && (c.words[k].text == "echo" || c.words[k].text == "printf") {
		v = code(joinWords(c.words[k+1:]), anyDynamic(c.words[k+1:]), depth, self)
	}
	for _, d := range c.heredocs {
		v = worse(v, code(d.body, !d.literal, depth, self))
	}
	for _, h := range c.herestr {
		v = worse(v, code(h, false, depth, self))
	}
	return v
}

// printed judges code whose output a shell runs (source <(…)), like a
// pipeline into that shell.
func printed(text string, depth int, self string) verdict {
	if depth > maxDepth {
		return textVerdict(text)
	}
	p := &parser{src: text, depth: depth + 1, self: self}
	p.parse()
	if p.bad {
		return worse(textVerdict(text), denyDynamic)
	}
	v := allow
	for _, pl := range p.pipes {
		for _, c := range pl.cmds {
			v = worse(v, c.printed(depth+1, self))
		}
	}
	return v
}

// runsShell reports whether c runs a shell or ssh that reads its stdin as
// code, directly or through wrappers (xargs sh -c, timeout 5 bash), and
// whether that shell runs here (not ssh).
func (c *simpleCmd) runsShell(self string, depth int) (shell, local bool) {
	k := commandWord(c.words, 0)
	for k >= 0 && k < len(c.words) {
		name := base(c.words[k].text)
		switch {
		case name == "ssh":
			return true, false
		case shells[name] || name == "eval" || name == "source" || name == ".":
			return true, true
		case name == "find":
			for _, w := range c.words[k+1:] {
				if n := base(w.text); shells[n] {
					return true, true
				} else if n == "ssh" {
					shell = true
				}
			}
			return shell, false
		case wrappers[name]:
			k, _ = wrapped(name, c.words, k, self, depth)
		default:
			return false, false
		}
	}
	return false, false
}

type codeText struct {
	text   string
	judged bool
}

// codeOf returns the text words make when joined, once for each value a
// variable among them can have (scope.literal): CMD='qm list'; ssh h "$CMD"
// is the code qm list. A variable with no known value stays as written. With
// too many combinations, the words are judged as written and every value on
// its own: words are joined with spaces, so no command can be spelled across
// two values, and no value is left unjudged.
func (c *simpleCmd) codeOf(ws []word) []codeText {
	out := []codeText{{}}
	resolved := false
	var each []codeText // every value of every word, for the fallback
	for i, w := range ws {
		texts := []string{w.text}
		if vals := c.scope.literal(w); len(vals) > 0 {
			texts, resolved = vals, true
		} else if vals := c.scope.candidates(w); len(vals) > 0 {
			// Not followed: judged as computed, and as each value it was given.
			texts = append(append([]string{}, vals...), w.text)
		}
		if len(texts) > 1 || texts[0] != w.text {
			for _, t := range texts {
				each = append(each, codeText{text: t})
			}
		}
		var next []codeText
		for _, o := range out {
			for _, t := range texts {
				if i > 0 {
					t = " " + t
				}
				next = append(next, codeText{text: o.text + t})
			}
		}
		if len(next) > 16 {
			for _, w := range ws[i+1:] {
				for _, t := range append(c.scope.literal(w), c.scope.candidates(w)...) {
					each = append(each, codeText{text: t})
				}
			}
			return append([]codeText{{text: joinWords(ws), judged: anyDynamic(ws)}}, each...)
		}
		out = next
	}
	for i := range out {
		// A value written in this command was not parsed where it was
		// assigned (it was quoted there), so its substitutions are judged now.
		out[i].judged = !resolved && anyDynamic(ws)
	}
	return out
}

// remote is the verdict on code that runs on an SSH host. A computed name
// there is not denied: the host's login shell may not be a POSIX shell at
// all (PowerShell reads $x=… as an assignment), scripts there name their
// tools in variables ($V - <<'E'), and sudo on the host has no terminal and
// no password, so it fails on its own unless the host allows it without one.
// sudo written in any form the shell would spell out is still denied.
func remote(v verdict) verdict {
	if v == denyDynamic {
		return allow
	}
	return v
}

func anyDynamic(words []word) bool {
	for _, w := range words {
		if w.dynamic {
			return true
		}
	}
	return false
}

func joinWords(words []word) string {
	text := make([]string, len(words))
	for i, w := range words {
		text[i] = w.text
	}
	return strings.Join(text, " ")
}

// globRoot reports whether w, as a file name pattern, can match sudo or
// sshpass: /usr/bin/su?o, /usr/bin/s[u]do. A pattern with no letter of its
// own (*, dir/*) is a list of files, not a way to spell a program.
func globRoot(w word) bool {
	pat := base(w.text)
	if !w.glob || strings.Trim(pat, "*?[]!^") == "" {
		return false
	}
	for _, name := range []string{"sudo", "sshpass"} {
		if ok, _ := path.Match(pat, name); ok {
			return true
		}
	}
	return false
}

// namesRoot reports whether a word that may be a program is sudo or sshpass:
// by name, by one of its brace expansions, or as a pattern that matches them.
func namesRoot(w word) bool {
	for _, t := range append([]string{w.text}, w.alts...) {
		if n := base(t); n == "sudo" || n == "sshpass" {
			return true
		}
	}
	return globRoot(w)
}

func (c *simpleCmd) textVerdict() verdict {
	v := allow
	text := make([]string, len(c.words))
	for i, w := range c.words {
		v = worse(v, wordVerdict(w))
		if globRoot(w) {
			v = worse(v, denyRoot)
		}
		text[i] = w.text
	}
	// A credential-store read spans several words (security … -w), so the
	// words are judged together as well.
	v = worse(v, textVerdict(strings.Join(text, " ")))
	for _, d := range c.heredocs {
		v = worse(v, textVerdict(d.body))
	}
	for _, h := range c.herestr {
		v = worse(v, textVerdict(h))
	}
	return v
}

// verdict judges one simple command and reports whether it runs shell code
// taken from its arguments or stdin.
func (c *simpleCmd) verdict(full, self string, depth int) (verdict, bool) {
	k := commandWord(c.words, 0)
	if k < 0 {
		return allow, false
	}
	for {
		cw := c.words[k]
		name := base(cw.text)
		switch {
		case name == "sudo" || name == "sshpass" || namesRoot(cw):
			return denyRoot, false
		case name == "psudo" && isSelf(cw.text, self):
			// The real psudo runs its arguments as root; sudo inside is harmless.
			// A credential-store read is not: it prints a secret whoever runs
			// it. So the command psudo is given is judged for that alone.
			if rest := psudoCommand(c.words[k+1:]); len(rest) > 0 {
				if v, _ := (&simpleCmd{words: rest}).verdict(full, self, depth); v == denyCache {
					return denyCache, false
				}
			}
			return allow, false
		case cw.opaque || cw.dynamic && wordVerdict(cw) != allow:
			// $'\x..' cannot be read at all, and ${SUDO:-sudo} names sudo.
			return denyRoot, true
		case (cw.glob || len(cw.alts) > 0) && !(c.pattern && len(c.words) == 1):
			// A pattern (./*/tool) or a brace expansion ({a,b}) as the
			// program: which program runs depends on what it expands to.
			return denyDynamic, true
		case cw.dynamic && (cw.end > len(full) || !literalProgram(full[cw.start:cw.end])):
			// The program is computed ($cmd, ${x:-…}): it cannot be judged,
			// so deny, asking for the name to be written out. When only its
			// folder is computed, name is the program, judged below.
			return denyDynamic, true
		case cacheTools[name]:
			if credentialRead(name, c.words[k+1:]) {
				return denyCache, false
			}
			return allow, false
		case carriers[name] || interpreter.MatchString(name):
			return worse(c.textVerdict(), c.codeVerdict(name, k, self, depth)), true
		case wrappers[name]:
			// Any later word that names sudo or sshpass is what it runs.
			for _, w := range c.words[k+1:] {
				if namesRoot(w) {
					return denyRoot, false
				}
			}
			// The same for a credential-store read: the program the wrapper
			// runs may come after a value (timeout 5 security …, find . -exec …).
			if readsStore(c.words[k+1:]) {
				return denyCache, false
			}
			if name == "find" {
				return c.findVerdict(k, full, self, depth), false
			}
			next, v := wrapped(name, c.words, k, self, depth)
			if v != allow {
				return v, false
			}
			if next >= len(c.words) {
				return allow, false
			}
			if name == "watch" || name == "sg" {
				// They hand the rest to sh -c as one string.
				return worse(c.textVerdict(), code(joinWords(c.words[next:]), anyDynamic(c.words[next:]), depth, self)), true
			}
			k = next
			continue
		case dataCommands[name]:
			return c.dataVerdict(name, k), false
		}
		// Unknown program: fail closed on its full text.
		return c.textVerdict(), false
	}
}

// wordVerdict judges one word as text; $'…' content cannot be judged.
func wordVerdict(w word) verdict {
	if w.opaque {
		return denyRoot
	}
	v := textVerdict(w.text)
	for _, a := range w.alts {
		v = worse(v, textVerdict(a))
	}
	return v
}

// codeVerdict parses and judges the code a shell carrier at k is given: the
// -c code of a shell, its here-documents when it reads stdin, the words of
// eval, the remote command of ssh and its *Command options, su -c and trap.
// Assignments before a shell (PS4=…, BASH_ENV=…) can be code too.
func (c *simpleCmd) codeVerdict(name string, k int, self string, depth int) verdict {
	sub := func(text string, judged bool) verdict {
		if name == "fish" && strings.Contains(text, `\`) {
			return denyRoot // fish's own backslash escapes can spell any word
		}
		return code(text, judged, depth, self)
	}
	// subWords judges the code that words make, once for each value a
	// variable among them was given in this command (ssh host "$CMD").
	subWords := func(ws []word) verdict {
		r := allow
		for _, ct := range c.codeOf(ws) {
			r = worse(r, sub(ct.text, ct.judged))
		}
		return r
	}
	v := allow
	// What reaches the shell's stdin, or a file it reads from <(…), can be
	// code: bash /dev/stdin <<'EOF', source <(echo …).
	stdin := func() {
		for _, d := range c.heredocs {
			v = worse(v, sub(d.body, !d.literal))
		}
		for _, h := range c.herestr {
			v = worse(v, sub(h, false))
		}
		for _, ps := range c.procsub {
			v = worse(v, printed(ps, depth, self))
		}
	}
	args := c.words[k+1:]
	switch {
	case shells[name]:
		for _, w := range c.words[:k] {
			if name, value, ok := strings.Cut(w.text, "="); ok && promptVars[name] {
				v = worse(v, sub(value, w.dynamic))
			}
		}
		hasC := false
		for i := 0; i < len(args); i++ {
			t := args[i].text
			if t == "--" {
				if i+1 >= len(args) {
					break
				}
				i++
				t = args[i].text
			} else if len(t) > 1 && (t[0] == '-' || t[0] == '+') {
				switch t {
				case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
					i++
				default:
					hasC = hasC || t[1] != '-' && strings.ContainsRune(t[1:], 'c')
				}
				continue
			}
			if hasC {
				v = worse(v, subWords(args[i:i+1]))
			}
			break // otherwise a script file, which the guard cannot see
		}
		stdin()
	case name == "eval":
		v = subWords(args)
	case name == "ssh":
		for i := 0; i < len(args); i++ {
			t := args[i].text
			if t == "--" {
				if i++; i >= len(args) {
					break
				}
			} else if len(t) > 1 && t[0] == '-' {
				for j := 1; j < len(t); j++ {
					if strings.IndexByte("BbcDEeFIiJLlmOoPpQRSWw", t[j]) < 0 {
						continue
					}
					value, judged := t[j+1:], args[i].dynamic
					if value == "" && i+1 < len(args) {
						i++
						value, judged = args[i].text, args[i].dynamic
					}
					if t[j] == 'o' {
						key, rest, _ := strings.Cut(strings.TrimLeft(value, " "), "=")
						if strings.HasSuffix(strings.ToLower(strings.TrimSpace(key)), "command") {
							v = worse(v, subWords([]word{{text: rest, dynamic: judged}}))
						}
					}
					break
				}
				continue
			}
			// args[i] is the host; the rest is the remote command.
			if i+1 < len(args) {
				v = worse(v, remote(subWords(args[i+1:])))
			}
			break
		}
		saved := v
		v = allow
		stdin()
		v = worse(saved, remote(v))
	case name == "su":
		for i, w := range args {
			if (w.text == "-c" || w.text == "--command") && i+1 < len(args) {
				v = worse(v, subWords(args[i+1:i+2]))
			} else if value, ok := strings.CutPrefix(w.text, "--command="); ok {
				v = worse(v, sub(value, w.dynamic))
			}
		}
	case name == "trap":
		if len(args) > 0 && args[0].text == "--" {
			args = args[1:]
		}
		if len(args) > 0 && !strings.HasPrefix(args[0].text, "-") {
			v = subWords(args[:1])
		}
	case name == "source" || name == ".":
		stdin()
	}
	return v
}

// findVerdict judges find: each -exec, -execdir, -ok or -okdir runs the
// command up to ";" or "+", which is judged as a command of its own. The
// other words are paths and tests, judged as text.
func (c *simpleCmd) findVerdict(k int, full, self string, depth int) verdict {
	v := allow
	for i := k + 1; i < len(c.words); i++ {
		switch c.words[i].text {
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(c.words) && c.words[j].text != ";" && c.words[j].text != "+" {
				j++
			}
			if j > i+1 {
				sv, _ := (&simpleCmd{words: c.words[i+1 : j]}).verdict(full, self, depth)
				v = worse(v, sv)
			}
			i = j
		default:
			v = worse(v, wordVerdict(c.words[i]))
		}
	}
	return v
}

// wrapSpec describes how a wrapper finds the program it runs.
type wrapSpec struct {
	values string   // short options that take a value
	long   []string // long options that take the next word as their value
	code   string   // short options whose value is shell code
	pos    int      // positional arguments before the program
}

var wrapSpecs = map[string]wrapSpec{
	"env":         {values: "uCSP", long: []string{"--unset", "--chdir", "--split-string"}, code: "S"},
	"timeout":     {values: "sk", long: []string{"--signal", "--kill-after"}, pos: 1},
	"nice":        {values: "n", long: []string{"--adjustment"}},
	"ionice":      {values: "cnp", long: []string{"--class", "--classdata", "--pid"}},
	"xargs":       {values: "aEdILnPs", long: []string{"--arg-file", "--delimiter", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"}},
	"stdbuf":      {values: "ioe", long: []string{"--input", "--output", "--error"}},
	"chrt":        {pos: 1},
	"taskset":     {pos: 1},
	"flock":       {values: "wEc", long: []string{"--timeout", "--conflict-exit-code", "--command"}, code: "c", pos: 1},
	"exec":        {values: "a"},
	"caffeinate":  {values: "tw"},
	"doas":        {values: "uC"},
	"runuser":     {values: "ugGcs", long: []string{"--user", "--group", "--supp-group", "--command", "--shell"}, code: "c"},
	"chroot":      {pos: 1},
	"sg":          {pos: 1},
	"script":      {values: "cEIOTB", code: "c", pos: 1},
	"strace":      {values: "oepsSuEIXbaP"},
	"ltrace":      {values: "oepsuEna"},
	"watch":       {values: "n", long: []string{"--interval"}},
	"systemd-run": {values: "pEuMH", long: []string{"--property", "--setenv", "--unit", "--machine", "--host"}},
	"nsenter":     {values: "tSG", long: []string{"--target", "--setuid", "--setgid"}},
}

// wrapped returns the index of the program a wrapper at k runs, skipping its
// options, their values, assignments (env) and positional arguments (the
// duration of timeout). It denies an option value or positional argument with
// an unquoted expansion, a pattern or a brace expansion: bash splits such a
// word, and its pieces could be the program. An option value that is shell
// code (env -S, flock -c, script -c) is parsed and judged.
func wrapped(name string, words []word, k int, self string, depth int) (int, verdict) {
	spec := wrapSpecs[name]
	pos, opts := spec.pos, true
	v := allow
	check := func(w word) {
		if w.split || w.glob || w.opaque || len(w.alts) > 0 {
			v = worse(v, denyDynamic)
		}
	}
	isLong := func(t string) bool {
		for _, l := range spec.long {
			if t == l {
				return true
			}
		}
		return false
	}
	i := k + 1
	for i < len(words) {
		w := words[i]
		t := w.text
		switch {
		case opts && t == "--":
			opts = false
			i++
			continue
		case opts && strings.HasPrefix(t, "--"):
			opt, value, eq := strings.Cut(t, "=")
			judged := w.dynamic
			if !eq && isLong(opt) && i+1 < len(words) {
				i++
				value, judged = words[i].text, words[i].dynamic
				check(words[i])
			}
			if opt == "--split-string" || opt == "--command" {
				v = worse(v, code(value, judged, depth, self))
			}
			i++
			continue
		case opts && len(t) > 1 && t[0] == '-':
			for j := 1; j < len(t); j++ {
				if strings.IndexByte(spec.values, t[j]) < 0 {
					continue
				}
				value, judged := t[j+1:], w.dynamic
				if value == "" && i+1 < len(words) {
					i++
					value, judged = words[i].text, words[i].dynamic
					check(words[i])
				}
				if strings.IndexByte(spec.code, t[j]) >= 0 {
					v = worse(v, code(value, judged, depth, self))
				}
				break
			}
			i++
			continue
		case assignment.MatchString(t):
			i++
			continue
		case pos > 0:
			pos--
			check(w)
			i++
			continue
		}
		return i, v
	}
	return len(words), v
}

// commitCluster is git commit flags that take no value, ending in -m.
var commitCluster = regexp.MustCompile(`^-[aeinopqsv]+m$`)

// textArgs are data programs with no option that runs a program, so their
// arguments are always text.
var textArgs = map[string]bool{"echo": true, "printf": true, "grep": true, "egrep": true, "fgrep": true}

// dataVerdict judges a data program at index k. Its here-documents and
// here-strings are text. Its arguments are text only for textArgs and for
// the message of git commit -m. Everything else, including variables set
// before it (GIT_PAGER=…, LESSOPEN=…) and options that run a program
// (man -P, rg --pre, sort --compress-program, git --upload-pack), is judged
// as text.
func (c *simpleCmd) dataVerdict(name string, k int) verdict {
	v := allow
	for _, w := range c.words[:k] {
		v = worse(v, wordVerdict(w))
	}
	if textArgs[name] {
		return v
	}
	args := c.words[k+1:]
	commit := name == "git" && len(args) > 0 && args[0].text == "commit"
	for i := 0; i < len(args); i++ {
		t := args[i].text
		if commit && (t == "-m" || t == "--message" || commitCluster.MatchString(t)) {
			i++ // the message itself (-m, or a cluster ending in it: -am, -qm)
			continue
		}
		if commit && (strings.HasPrefix(t, "-m") || strings.HasPrefix(t, "--message=")) {
			continue
		}
		v = worse(v, wordVerdict(args[i]))
	}
	return v
}

// isSelf reports whether a command word names the installed psudo: by path
// (~/ and $HOME/ expanded) or, for a bare name, through PATH, and only when it
// resolves to the same file.
func isSelf(text, self string) bool {
	if self == "" {
		return false
	}
	candidate := text
	if home, err := os.UserHomeDir(); err == nil {
		for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
			if strings.HasPrefix(candidate, prefix) {
				candidate = filepath.Join(home, candidate[len(prefix):])
			}
		}
	}
	if !strings.Contains(candidate, "/") {
		found, err := exec.LookPath(candidate)
		if err != nil {
			return false
		}
		candidate = found
	}
	return resolved(candidate) == resolved(self)
}

func resolved(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}
