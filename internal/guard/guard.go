// Package guard implements the harness hooks: the Claude Code PreToolUse
// policy that denies bare sudo/sshpass (spec §6.4), and the Codex
// SessionStart context that introduces psudo.
package guard

import (
	"encoding/json"
	"io"
	"regexp"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
)

// pattern matches sudo or sshpass as standalone words, like grep -w.
// "psudo" does not match because "p" is a word character.
var pattern = regexp.MustCompile(`(^|[^A-Za-z0-9_])(sudo|sshpass)([^A-Za-z0-9_]|$)`)

// Denied reports whether a Bash command must be refused: it would run sudo or
// sshpass, or read psudo's password cache (see shell.go).
func Denied(command string) bool { return judge(command, "") != allow }

// Reason is shown to the model when a command is denied: one the guard could
// not convert to psudo by itself. A harness tends to read a denial as a stop,
// so it says plainly that the task goes on with psudo.
func Reason(psudo string) string {
	p := shquote.Quote(psudo)
	return "Not run: on this machine root goes through psudo instead of sudo. This is not a refusal; continue the task by " +
		"running the same command through psudo: " + p + " <command> [args...] on this computer, " + p +
		" -H <ssh-host> <command> [args...] on an SSH host, or " + p + " sh -c '...' for a pipeline or a command that " +
		"reads stdin (psudo closes stdin). psudo takes no sudo options and shows the user its own password dialog; " +
		"never ask for or handle the password. If sudo is only text here (in a script or a file being written), " +
		"write that text with the file editing tool instead."
}

// DynamicReason is shown when the only problem is a program name the guard
// cannot read. It says what was wrong and that the command itself, ssh as
// root included, is fine once the name is written out.
const DynamicReason = "Not run: the program name in this command is computed (for example $S or ${cmd}), so psudo's " +
	"guard cannot see what would run, and it refuses whatever it cannot check for sudo. Nothing else in the " +
	"command was the problem. Run it again with the program's name or path written out literally in each command " +
	"(ssh -i key root@host '...', /path/to/psudo -H host ...), not taken from a variable. Variables in the " +
	"arguments are fine."

// Converted is the note added for the model when its command was converted.
func Converted(command string) string {
	return "psudo's guard converted this command's sudo to psudo, which runs it as root and shows the user its own " +
		"password dialog when one is needed. What ran: " + command + ". Use psudo directly next time."
}

// CacheReason is shown when a command would read psudo's password cache.
const CacheReason = "Credential-store secrets must never be read from the harness: psudo keeps the cached sudo " +
	"password and stored secrets there. Do not print secrets with security or secret-tool. To give a stored " +
	"secret to a command, run psudo --secret VAR=name -- <command> (psudo --secret-list shows the names); " +
	"to clear the sudo cache, run psudo --clear-cache."

type hookOutput struct {
	HookSpecificOutput map[string]string `json:"hookSpecificOutput"`
}

func encode(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func deny(out io.Writer, psudo string) error { return denyWith(out, Reason(psudo)) }

func denyWith(out io.Writer, reason string) error {
	return encode(out, hookOutput{map[string]string{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": reason,
	}})
}

// convert writes the decision that runs the converted command instead. It
// skips Claude Code's own permission prompt only in a session that bypasses
// permissions; any other mode asks, as it would have for sudo. The input is
// sent whole, because updatedInput replaces it.
func convert(out io.Writer, mode string, input map[string]json.RawMessage, command string) error {
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	input["command"] = raw
	decision := "ask"
	if mode == "bypassPermissions" {
		decision = "allow"
	}
	return encode(out, map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       decision,
		"permissionDecisionReason": "sudo converted to psudo: " + command,
		"updatedInput":             input,
		"additionalContext":        Converted(command),
	}})
}

// ClaudeCode reads a PreToolUse event. A command that runs sudo is converted
// to psudo when that can be done exactly (see rewrite.go); otherwise, and for
// sshpass and reads of psudo's credential store, it writes a deny decision.
// Unparseable input is denied (fail closed).
func ClaudeCode(in io.Reader, out io.Writer, psudo string) error {
	var event struct {
		ToolName       string          `json:"tool_name"`
		ToolInput      json.RawMessage `json:"tool_input"`
		PermissionMode string          `json:"permission_mode"`
	}
	if err := json.NewDecoder(in).Decode(&event); err != nil {
		return deny(out, psudo)
	}
	if event.ToolName != "" && event.ToolName != "Bash" {
		return nil
	}
	var input struct {
		Command *string `json:"command"`
	}
	if len(event.ToolInput) > 0 && json.Unmarshal(event.ToolInput, &input) != nil {
		return deny(out, psudo)
	}
	if input.Command == nil {
		return nil
	}
	switch judge(*input.Command, psudo) {
	case denyRoot:
		var whole map[string]json.RawMessage
		if converted, ok := Rewrite(*input.Command, psudo); ok && json.Unmarshal(event.ToolInput, &whole) == nil {
			return convert(out, event.PermissionMode, whole, converted)
		}
		return deny(out, psudo)
	case denyDynamic:
		return denyWith(out, DynamicReason)
	case denyCache:
		return denyWith(out, CacheReason)
	}
	return nil
}

// SessionContext is the SessionStart guidance that introduces psudo. The
// model learns about remote hosts here. Logging in as root with a key is
// allowed: the guard does not deny it, and psudo runs such a command without
// sudo, so the guidance must not steer the model away from it.
func SessionContext(psudo string, codex bool) string {
	p := shquote.Quote(psudo)
	s := "For authorized commands that need root, on this computer or on SSH hosts, use psudo: run " +
		p + " <command> [args...] on this computer, or " + p + " -H <ssh-host> <command> [args...] on a host reached over SSH. " +
		"For root on a remote host use psudo -H, not ssh <host> sudo ..., sudo -S, or sshpass. " +
		"A host you log in to as root needs no sudo: psudo -H root@<host> runs the command directly with no dialog, " +
		"and plain ssh root@<host> with a key is fine too. " +
		"The arguments are passed through exactly; use " + p + " sh -c '...' for pipelines; psudo takes no sudo options. " +
		"psudo shows the user a native dialog naming the host and command for the sudo password, and, if the host " +
		"needs a code or password to log in over SSH, a dialog for that too. Never ask the user for a password or " +
		"code in chat, and never pipe one into a command. Keep the actual command visible in the tool call. " +
		"Exit 251: the user cancelled; stop that privileged action. 252: authentication failed (the psudo: line says " +
		"WRONG PASSWORD, NOT PERMITTED or AUTHENTICATION FAILED); report it and do not retry another way. " +
		"Exit 252 with NO SUDO means the host has no sudo and the account psudo logged in as is not root: if root " +
		"may log in to that host, run it again with -H root@<host>. " +
		"255: the SSH connection or login failed. The command's stdin is closed; a command that needs a terminal " +
		"must be run by the user. " +
		"For a command that needs a stored secret (an API token, a database password), run " + p +
		" --secret VAR=name [--secret-file VAR=name] [-H <ssh-host>] -- <command> [args...]: the command runs as " +
		"the user, not root, with the secret in VAR (or a temporary file whose path is in VAR). psudo shows the user " +
		"a dialog only when it needs something: the value of a secret it does not have, or a decision about a stored " +
		"secret that no rule covers yet. " + p + " --secret-list shows the stored names and which commands may use them. " +
		"Name a secret after the environment variable the project uses for it, in lower case with dashes " +
		"(STRIPE_API_KEY is stripe-api-key): psudo then also finds its value in the project's git-ignored .env.local or .env. " +
		"If psudo has no value for the secret yet, still run the command: psudo asks the user to enter the value in a dialog " +
		"and, unless the user chooses to save it, keeps it for this session only, so a new session asks again. " +
		"Never ask the user to run psudo or edit its config themselves. " +
		"Never ask the user for a secret in chat, and never read one yourself from the OS credential store or from an env file. " +
		"Keep using the variable a secret was first used with: its rule names it, and another one is refused. " +
		"A value from an env file cannot be combined with a stored secret in one command. " +
		"Exit 253: the user's rules do not allow that use; tell the user which rule is missing rather than finding another way."
	if codex {
		s += " Follow normal sandbox escalation and approval requirements; psudo does not grant approval."
	}
	return s
}

// CodexContext is the SessionStart guidance for Codex.
func CodexContext(psudo string) string { return SessionContext(psudo, true) }

// Codex handles a Codex hook event, emitting context only for SessionStart.
func Codex(in io.Reader, out io.Writer, psudo string) error {
	return SessionStart(in, out, psudo, true)
}

// SessionStart writes the context for a SessionStart event and nothing for
// any other event.
func SessionStart(in io.Reader, out io.Writer, psudo string, codex bool) error {
	var event struct {
		Name string `json:"hook_event_name"`
	}
	if err := json.NewDecoder(in).Decode(&event); err != nil {
		return err
	}
	if event.Name != "SessionStart" {
		return nil
	}
	return encode(out, map[string]map[string]string{"hookSpecificOutput": {
		"hookEventName": "SessionStart", "additionalContext": SessionContext(psudo, codex),
	}})
}
