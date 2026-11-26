// Package install registers psudo with Claude Code and Codex and removes the
// earlier Python/shell integration files.
package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/cache"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/shquote"
	"github.com/MikeRzDev/harness-secrets-sudo-hook/internal/sysbin"
)

const (
	ClaudeHookCommand    = `"$HOME"/.claude/hooks/psudo --hook=claude-code` // expanded by the hook shell; quoted for spaces
	ClaudeSessionCommand = `"$HOME"/.claude/hooks/psudo --hook=claude-code-session-start`
	// ClaudeSessionEndCommand forgets the secrets kept for a session when it ends.
	ClaudeSessionEndCommand = `"$HOME"/.claude/hooks/psudo --hook=claude-code-session-end`
	// sessionEndTimeout is in seconds. Claude Code gives SessionEnd hooks 1.5
	// seconds unless the hook asks for more, and the credential store can be slower.
	sessionEndTimeout   = 15
	claudeLegacyCommand = "$HOME/.claude/hooks/sudo-check.sh"
)

var (
	claudeLegacyFiles = []string{"sudo-check.sh", "askpass.sh", "reaper.sh", "harness_cache.py"}
	codexLegacyFiles  = []string{"askpass.sh", "codex-sudo", "context.py", "harness_cache.py"}
)

// Installer carries every side-effecting dependency so tests can isolate it.
type Installer struct {
	Home      string
	CodexHome string
	GOOS      string
	UID       int
	Exe       string // the binary to install
	Exec      cache.ExecFunc
	Store     func(harness string) (cache.Store, error)
	CheckDeps bool
	Out       io.Writer
	// AppDir is where psudo.app goes on macOS (/Applications); "" skips it.
	AppDir string
}

func (in *Installer) say(format string, args ...any) { fmt.Fprintf(in.Out, format+"\n", args...) }

func (in *Installer) reaper() cache.Reaper {
	return cache.Reaper{Home: in.Home, UID: in.UID, Exec: in.Exec}
}

// ClaudeDir is where the Claude Code copy of psudo lives.
func (in *Installer) ClaudeDir() string { return filepath.Join(in.Home, ".claude", "hooks") }

// CodexDir is where the Codex copy of psudo lives.
func (in *Installer) CodexDir() (string, error) {
	home := in.CodexHome
	if home == "" {
		home = filepath.Join(in.Home, ".codex")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvePath(abs), "root-hook"), nil
}

// resolvePath resolves symlinks in the longest existing prefix of an absolute
// path, like Python's Path.resolve(strict=False).
func resolvePath(p string) string {
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	return filepath.Join(resolvePath(parent), filepath.Base(p))
}

func (in *Installer) checkDependencies() error {
	var missing []string
	need := func(path string) {
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, path)
		}
	}
	switch in.GOOS {
	case "darwin":
		for _, p := range []string{"/usr/bin/security", "/usr/bin/osascript", "/bin/launchctl"} {
			need(p)
		}
	case "linux":
		if sysbin.Find("secret-tool") == "" {
			missing = append(missing, "secret-tool (Ubuntu: sudo apt install libsecret-tools)")
		}
		if sysbin.Find("zenity") == "" && sysbin.Find("kdialog") == "" && sysbin.Find("ssh-askpass") == "" {
			in.say("warning: no password dialog found; install zenity, kdialog, or ssh-askpass")
		}
	default:
		return cache.ErrUnsupported
	}
	if sysbin.Find("sudo") == "" {
		missing = append(missing, "sudo")
	}
	if sysbin.Find("ssh") == "" {
		in.say("warning: ssh not found; psudo -H <host> will not work until OpenSSH is installed")
	}
	if len(missing) > 0 {
		return errors.New("missing required tools: " + strings.Join(missing, ", "))
	}
	return nil
}

// InstallClaudeCode copies psudo to ~/.claude/hooks and registers the PreToolUse guard.
func (in *Installer) InstallClaudeCode() error {
	if in.CheckDeps {
		if err := in.checkDependencies(); err != nil {
			return err
		}
	}
	settings := filepath.Join(in.Home, ".claude", "settings.json")
	root, existed, err := readSettings(settings)
	if err != nil {
		return err
	}
	groups, err := eventGroups(root, "PreToolUse")
	if err != nil {
		return err
	}
	groups = removeHandlers(groups, func(c string) bool { return c == claudeLegacyCommand })
	if !hasHandler(groups, ClaudeHookCommand) {
		groups = append(groups, group("Bash", ClaudeHookCommand, 0))
	}
	setEvent(root, "PreToolUse", groups)
	// Session context tells the model about psudo -H up front; the guard only
	// fires on commands that contain sudo.
	session, err := eventGroups(root, "SessionStart")
	if err != nil {
		return err
	}
	if !hasHandler(session, ClaudeSessionCommand) {
		session = append(session, group("", ClaudeSessionCommand, 10))
	}
	setEvent(root, "SessionStart", session)
	// A secret kept "for this session only" is forgotten when the session ends.
	ended, err := eventGroups(root, "SessionEnd")
	if err != nil {
		return err
	}
	if !hasHandler(ended, ClaudeSessionEndCommand) {
		ended = append(ended, group("", ClaudeSessionEndCommand, sessionEndTimeout))
	}
	setEvent(root, "SessionEnd", ended)

	configPath, err := cache.InitConfig()
	if err != nil {
		return fmt.Errorf("config %s: %w", configPath, err)
	}
	dir := in.ClaudeDir()
	binary := filepath.Join(dir, "psudo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := copyBinary(in.Exe, binary); err != nil {
		return err
	}
	if existed {
		backupOnce(settings, settings+".bak")
	}
	if err := writeSettings(settings, root); err != nil {
		return err
	}

	// Remove the earlier shell/Python integration and its caches.
	removeFiles(dir, claudeLegacyFiles)
	switch in.GOOS {
	case "darwin":
		in.reaper().RemoveLegacy("com.claude.sudo-reaper")
		in.Exec("/usr/bin/security", []string{"delete-generic-password", "-s", "claude-sudo", "-a", cache.Account()}, nil)
		if err := in.reaper().Install("claude-code", binary, configPath); err != nil {
			return err
		}
	case "linux":
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir == "" {
			runtimeDir = fmt.Sprintf("/run/user/%d", in.UID)
		}
		os.Remove(filepath.Join(runtimeDir, "claude-sudo.cache"))
	}
	in.say("Installed %s", binary)
	in.say("Registered the PreToolUse guard, the SessionStart context and the SessionEnd cleanup in %s", settings)
	in.say("Settings: %s (password cache: off by default; set \"enabled\": true to cache local commands)", configPath)
	in.say("Restart Claude Code, then ask it to run: %s id -u", binary)
	return nil
}

// UninstallClaudeCode removes the guard registration, cache entry, reaper and files.
func (in *Installer) UninstallClaudeCode() error {
	settings := filepath.Join(in.Home, ".claude", "settings.json")
	root, existed, err := readSettings(settings)
	if err != nil {
		return err
	}
	if existed {
		groups, err := eventGroups(root, "PreToolUse")
		if err != nil {
			return err
		}
		groups = removeHandlers(groups, func(c string) bool { return c == ClaudeHookCommand || c == claudeLegacyCommand })
		setEvent(root, "PreToolUse", groups)
		session, err := eventGroups(root, "SessionStart")
		if err != nil {
			return err
		}
		setEvent(root, "SessionStart", removeHandlers(session, func(c string) bool { return c == ClaudeSessionCommand }))
		ended, err := eventGroups(root, "SessionEnd")
		if err != nil {
			return err
		}
		setEvent(root, "SessionEnd", removeHandlers(ended, func(c string) bool { return c == ClaudeSessionEndCommand }))
		if err := writeSettings(settings, root); err != nil {
			return err
		}
	}
	errs := in.clearCache("claude-code")
	dir := in.ClaudeDir()
	removeFiles(dir, append([]string{"psudo"}, claudeLegacyFiles...))
	in.say("Removed psudo from %s and its hook from %s", dir, settings)
	in.removeApp()
	return errs
}

// InstallCodex copies psudo to $CODEX_HOME/root-hook and registers SessionStart context.
func (in *Installer) InstallCodex() error {
	if in.CheckDeps {
		if err := in.checkDependencies(); err != nil {
			return err
		}
	}
	dest, err := in.CodexDir()
	if err != nil {
		return err
	}
	settings := filepath.Join(filepath.Dir(dest), "hooks.json")
	binary := filepath.Join(dest, "psudo")
	command := shquote.Quote(binary) + " --hook=codex-session-start"
	legacy := "python3 " + shquote.Quote(filepath.Join(dest, "context.py"))
	root, existed, err := readSettings(settings)
	if err != nil {
		return err
	}
	groups, err := eventGroups(root, "SessionStart")
	if err != nil {
		return err
	}
	groups = removeHandlers(groups, func(c string) bool { return c == legacy })
	if !hasHandler(groups, command) {
		groups = append(groups, group("", command, 10))
	}
	setEvent(root, "SessionStart", groups)

	configPath, err := cache.InitConfig()
	if err != nil {
		return fmt.Errorf("config %s: %w", configPath, err)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	if err := copyBinary(in.Exe, binary); err != nil {
		return err
	}
	if existed {
		backupOnce(settings, filepath.Join(filepath.Dir(settings), "hooks.json.before-root-hook"))
	}
	if err := writeSettings(settings, root); err != nil {
		return err
	}
	removeFiles(dest, codexLegacyFiles)
	if in.GOOS == "darwin" {
		if err := in.reaper().Install("codex", binary, configPath); err != nil {
			return err
		}
	}
	in.say("Installed %s", binary)
	in.say("Registered the SessionStart hook in %s", settings)
	in.say("Open /hooks in Codex to review and trust the hook, then start a new session. No sudo command has been run.")
	return nil
}

// UninstallCodex removes the Codex registration, cache entry, reaper and files.
func (in *Installer) UninstallCodex() error {
	dest, err := in.CodexDir()
	if err != nil {
		return err
	}
	settings := filepath.Join(filepath.Dir(dest), "hooks.json")
	binary := filepath.Join(dest, "psudo")
	command := shquote.Quote(binary) + " --hook=codex-session-start"
	legacy := "python3 " + shquote.Quote(filepath.Join(dest, "context.py"))
	root, existed, err := readSettings(settings)
	if err != nil {
		return err
	}
	if existed {
		groups, err := eventGroups(root, "SessionStart")
		if err != nil {
			return err
		}
		groups = removeHandlers(groups, func(c string) bool { return c == command || c == legacy })
		setEvent(root, "SessionStart", groups)
		if err := writeSettings(settings, root); err != nil {
			return err
		}
	}
	errs := in.clearCache("codex")
	removeFiles(dest, append([]string{"psudo"}, codexLegacyFiles...))
	os.Remove(dest) // only succeeds when empty
	in.say("Removed the Codex root hook from %s", dest)
	in.removeApp()
	return errs
}

func (in *Installer) clearCache(harness string) error {
	var errs []error
	store, err := in.Store(harness)
	if err == nil {
		err = store.Clear()
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("could not clear the cached password: %w", err))
	}
	if in.GOOS == "darwin" {
		if err := in.reaper().Remove(harness); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func removeFiles(dir string, names []string) {
	for _, name := range names {
		os.Remove(filepath.Join(dir, name))
	}
}

// copyBinary installs src at dst through a temporary file and rename, so a
// running copy is never modified in place.
func copyBinary(src, dst string) error {
	if info, err := os.Lstat(dst); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink: %s", dst)
		}
		if srcInfo, err := os.Stat(src); err == nil && os.SameFile(info, srcInfo) {
			return nil
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".psudo-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func backupOnce(path, backup string) {
	if _, err := os.Lstat(backup); err == nil {
		return
	}
	if data, err := os.ReadFile(path); err == nil {
		os.WriteFile(backup, data, 0o600)
	}
}
