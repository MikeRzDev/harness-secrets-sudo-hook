package guard

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func decide(t *testing.T, input string) string {
	t.Helper()
	var out bytes.Buffer
	if err := ClaudeCode(strings.NewReader(input), &out, "/home/u/.claude/hooks/psudo"); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return "allow"
	}
	var res struct{ HookSpecificOutput map[string]any }
	json.Unmarshal(out.Bytes(), &res)
	d, _ := res.HookSpecificOutput["permissionDecision"].(string)
	return d
}

// verdictOf is what the guard sees a command do, before any conversion.
func verdictOf(command string) string {
	if judge(command, "/home/u/.claude/hooks/psudo") == allow {
		return "allow"
	}
	return "deny"
}

func bash(command string) string {
	b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": command}})
	return string(b)
}

// The decision matrix from spec §6.4, plus a few boundary cases.
func TestDecisionMatrix(t *testing.T) {
	for command, want := range map[string]string{
		"sudo apt install x":                    "deny",
		"ssh host sudo systemctl restart nginx": "deny",
		"echo secret | sudo -S id":              "deny",
		"sshpass -p pw ssh host":                "deny",
		"psudo apt install x":                   "allow",
		"psudo -H host systemctl restart nginx": "allow",
		"psudo ls && sudo rm x":                 "deny",
		"cat /etc/sudoers":                      "allow",
		"/usr/bin/sudo id":                      "deny",
		"echo ok\nsudo id":                      "deny",
		"(sudo id)":                             "deny",
		"~/.claude/hooks/psudo id -u":           "allow",
		"cat ~/.claude/hooks/psudo":             "allow",
		"grep error /var/log/sudo.log":          "allow",
		"ls /etc/sudoers.d":                     "allow",
		"grep pseudo notes.txt":                 "allow",

		// The project's own name holds the word between dashes. It is a name,
		// not the command, so paths and links with it are allowed.
		"cd /home/u/src/harness-secrets-sudo-hook && make test":                      "allow",
		"git clone https://github.com/MikeRzDev/harness-secrets-sudo-hook.git":       "allow",
		"go install github.com/MikeRzDev/harness-secrets-sudo-hook/cmd/psudo@latest": "allow",
		"ls harness-secrets-sudo-hook/docs harness-secrets-sudo-hook/cmd":            "allow",
		"sh -c 'cd harness-secrets-sudo-hook && make build'":                         "allow",
		"cd harness-secrets-sudo-hook && sudo make install":                          "deny",
		"sh -c 'cd harness-secrets-sudo-hook; sudo id'":                              "deny",
		"harness-secrets-sudo-hook/sudo id":                                          "deny",
		"env harness-secrets-sudo-hook/sudo id":                                      "deny",
		"ls harness-secrets-sudo-hook sudo":                                          "deny",
		"ls sudo-harness-secrets-sudo-hook":                                          "deny",
		"ls harness-secrets-sudo-hook-sudo":                                          "deny",
		"ls harness-secrets-sudo -hook":                                              "deny",
		"ls my-sudo-notes":                                                           "deny",

		// The word as data: these blocked real work before.
		"cat >> specs/PROGRESS.md <<'EOF'\n13. Ran `sudo fleet-ca krl push` through psudo.\nEOF": "allow",
		"cat > notes.md <<EOF\nsudo is denied; use psudo\nEOF":                                   "allow",
		`git commit -m "Explain why sudo is denied"`:                                             "allow",
		`grep -rn 'sudo' docs`:                                      "allow",
		`echo "run psudo, not sudo"`:                                "allow",
		"# sudo is not used here\nls":                               "allow",
		"/home/u/.claude/hooks/psudo sh -c 'sudo -u postgres psql'": "allow",
		"env cat > f <<'EOF'\nsudo\nEOF":                            "allow",
		"cat <<'EOF'\n$(sudo id)\nEOF":                              "allow",

		// Ways to actually run it: all denied.
		"env FOO=1 sudo id":          "deny",
		"FOO=1 sudo id":              "deny",
		"xargs sudo rm < list":       "deny",
		"nohup sudo id &":            "deny",
		"time sudo id":               "deny",
		"! sudo id":                  "deny",
		"exec sudo id":               "deny",
		"2>/dev/null sudo id":        "deny",
		`"sudo" id`:                  "deny",
		`s\udo id`:                   "deny",
		"'/usr/bin/sudo' id":         "deny",
		"echo $(sudo id)":            "deny",
		"echo \"$(sudo id)\"":        "deny",
		"x=`sudo id`":                "deny",
		"cat <<EOF\n$(sudo id)\nEOF": "deny",
		"ssh host 'sudo systemctl restart nginx'": "deny",
		"bash -c \"sudo id\"":                     "deny",
		`echo "sudo id" | sh`:                     "deny",
		"ssh host <<'EOF'\nsudo id\nEOF":          "deny",
		"sh <<< 'sudo id'":                        "deny",
		"S=sudo; $S id":                           "deny",
		"if true; then sudo id; fi":               "deny",
		"{ sudo id; }":                            "deny",
		"for h in a b; do sudo id; done":          "deny",
		"ls &&\nsudo id":                          "deny",
		"ls | sudo tee /etc/x":                    "deny",
		"echo 'unterminated sudo":                 "deny", // unparseable: falls back to the word match
		"eval \"sudo id\"":                        "deny",
		"watch sudo id":                           "deny",

		// Found by review: interpreters, more wrappers, unknown programs, fake psudo.
		"python3 - <<'EOF'\nprint('sudo')\nEOF":          "deny",
		"python3 -c 'import os; os.system(\"sudo id\")'": "deny",
		"perl -e 'system \"sudo id\"'":                   "deny",
		"awk 'BEGIN{system(\"sudo id\")}'":               "deny",
		"find . -name x -exec sudo rm {} +":              "deny",
		"setsid sudo id":                                 "deny",
		"flock /tmp/l sudo id":                           "deny",
		"make SUDO=sudo install":                         "deny",
		"/tmp/psudo sudo id":                             "deny",
		"psudo sh -c 'sudo id'":                          "deny",
		"git -c alias.x='!sudo id' x":                    "deny",
		"gh alias set x '!sudo id'":                      "deny",
		"echo 'sudo id' | python3":                       "deny",

		// Found by review: variables and exec options on data programs.
		"GIT_PAGER='sudo id' git log":                "deny",
		"env GIT_PAGER='sudo id' git log":            "deny",
		"LESSOPEN='|sudo id %s' less f":              "deny",
		"man -P 'sudo id' ls":                        "deny",
		"rg --pre 'sudo id' pattern":                 "deny",
		"sort --compress-program=sudo f":             "deny",
		"git --upload-pack='sudo x' fetch origin":    "deny",
		"git commit -m 'fix' --exec-path='sudo x'":   "deny",
		"git config alias.x '!sudo id'":              "deny",
		"ln -s /usr/bin/sudo ./x":                    "deny",
		"git commit -F - <<'EOF'\nExplain sudo\nEOF": "allow",
		"git commit --message='Explain sudo'":        "allow",
		"tee notes.md <<< 'use psudo, not sudo'":     "allow",

		// Found by review: computed names, ANSI-C quoting, ${…}, $((…)), case.
		`$'\x73udo' id`:                       "deny",
		`sh -c $'\x73udo id'`:                 "deny",
		"${SUDO:-sudo} id":                    "deny",
		"$EDITOR notes.md":                    "deny",
		"echo ${x:-$(sudo id)}":               "deny",
		"echo $(( $(sudo id) + 1 ))":          "deny",
		"echo $(case x in a) sudo id;; esac)": "deny",
		`echo $'tab\there'`:                   "allow",
		"echo $((1 + 2))":                     "allow",
		"echo ${HOME}/notes":                  "allow",
	} {
		if got := verdictOf(command); got != want {
			t.Errorf("%q: %s, want %s", command, got, want)
		}
	}
}

// A computed program name is denied with its own reason, which asks for the
// name to be written out; sudo anywhere in the command keeps the sudo reason.
func TestComputedProgramNameReason(t *testing.T) {
	reason := func(command string) string {
		var out bytes.Buffer
		if err := ClaudeCode(strings.NewReader(bash(command)), &out, "/home/u/.claude/hooks/psudo"); err != nil {
			t.Fatal(err)
		}
		var res struct{ HookSpecificOutput map[string]any }
		json.Unmarshal(out.Bytes(), &res)
		r, _ := res.HookSpecificOutput["permissionDecisionReason"].(string)
		return r
	}
	for _, command := range []string{
		`S="ssh -i /k root@192.168.8.234"; $S 'qm list'`,
		`P=/home/u/.claude/hooks/psudo; $P -H host id -u`,
		"$EDITOR notes.md",
	} {
		if got := reason(command); got != DynamicReason {
			t.Errorf("%q: reason %q, want the computed-name reason", command, got)
		}
	}
	for _, command := range []string{"${SUDO:-sudo} id", `$'\x73udo' id`, "$S x; sudo -k"} {
		if got := reason(command); got == DynamicReason || got == "" {
			t.Errorf("%q: reason %q, want the sudo reason", command, got)
		}
	}
	// Written out, the same root login is not the guard's business.
	if got := decide(t, bash(`ssh -i /k root@192.168.8.234 'qm list; pct list'`)); got != "allow" {
		t.Errorf("literal ssh root@host: %s, want allow", got)
	}
}

func TestPasswordCacheReadsAreDenied(t *testing.T) {
	for command, want := range map[string]string{
		"security find-generic-password -w -s harness-root-hook.claude-code": "deny",
		"/usr/bin/security find-generic-password -s harness-root-hook.codex": "deny",
		"secret-tool lookup application harness-root-hook harness codex":     "deny",
		"bash -c 'security find-generic-password -w -s harness-root-hook.x'": "deny",
		"security find-generic-password -s some-other-service":               "allow",
		"psudo --clear-cache":              "allow",
		"grep harness-root-hook README.md": "allow",
		// Reads that print any entry's secret could reach psudo's stored secrets.
		"security find-generic-password -a me -w":                "deny",
		"security find-generic-password -gs github":              "deny",
		"security -q find-internet-password -s x -w":             "deny",
		"security dump-keychain -d":                              "deny",
		"security find-generic-password $OPTS":                   "deny",
		"secret-tool search --all application x":                 "deny",
		"secret-tool lookup service github":                      "deny",
		"sh -c 'security find-generic-password -a me -w'":        "deny",
		"security add-generic-password -s harness-root-hook.x":   "deny",
		"security dump-keychain":                                 "allow",
		"security list-keychains":                                "allow",
		"secret-tool store --label=x service y":                  "allow",
		"/p/psudo --secret GH_TOKEN=github-token -- gh api user": "allow",

		// Found by audit: the read sits behind a wrapper's value, arrives on
		// security's stdin, or is the command given to psudo itself.
		"timeout 5 security find-generic-password -s foo -w":                              "deny",
		"nice -n 5 security find-generic-password -a me -w":                               "deny",
		`find . -maxdepth 0 -exec security find-generic-password -s x -w \;`:              "deny",
		"xargs -n 1 security find-generic-password -w -s":                                 "deny",
		"timeout 5 secret-tool lookup service github":                                     "deny",
		"timeout 5 security delete-generic-password -s harness-root-hook.approvals.rules": "deny",
		"echo 'find-generic-password -s x -w' | security -i":                              "deny",
		"security -i <<< 'find-generic-password -s x -w'":                                 "deny",
		"security -q -i":             "deny",
		"security -p '> ' -i":        "deny",
		"sh -c 'security -i < cmds'": "deny",
		"/home/u/.claude/hooks/psudo security find-generic-password -s x -w":         "deny",
		"/home/u/.claude/hooks/psudo sh -c 'security find-generic-password -s x -w'": "deny",
		"/home/u/.claude/hooks/psudo -H web1 secret-tool lookup service github":      "deny",
		"timeout 5 security list-keychains":                                          "allow",
		"security find-identity -v -p codesigning":                                   "allow",
		"/home/u/.claude/hooks/psudo ls /etc/security":                               "allow",
		"/home/u/.claude/hooks/psudo apt install libsecret-tools":                    "allow",
		"/home/u/.claude/hooks/psudo sh -c 'sudo -u postgres psql'":                  "allow",

		"/home/u/.claude/hooks/psudo timeout 5 security find-generic-password -s x -w":       "deny",
		"/home/u/.claude/hooks/psudo --secret T=x -- security find-generic-password -s x -w": "deny",
		"/home/u/.claude/hooks/psudo security find-generic-password $OPTS":                   "deny",
		// The word as an argument of another program is not a read.
		"find . -name security -print":                                                "allow",
		`timeout 30 grep -rn security "$PWD/docs"`:                                    "allow",
		"/home/u/.claude/hooks/psudo find /etc -name security -print":                 "allow",
		"/home/u/.claude/hooks/psudo vim /etc/security/limits.conf":                   "allow",
		"/home/u/.claude/hooks/psudo -H web1 --secret-file K=kube -- kubectl get pod": "allow",
	} {
		if got := verdictOf(command); got != want {
			t.Errorf("%q: %s, want %s", command, got, want)
		}
	}
	var out bytes.Buffer
	ClaudeCode(strings.NewReader(bash("security find-generic-password -w -s harness-root-hook.codex")), &out, "/p")
	if !strings.Contains(out.String(), "must never be read") {
		t.Fatalf("cache reason %s", out.String())
	}
}

// A command whose sudo can be converted runs as psudo instead of being
// denied; "" means it cannot be converted exactly and is denied.
func TestConversions(t *testing.T) {
	const p = "/home/u/.claude/hooks/psudo"
	for command, want := range map[string]string{
		"sudo apt install x":                        p + " apt install x",
		"sudo -n -E -u root -- systemctl restart x": p + " systemctl restart x",
		"sudo -nu root id":                          p + " id",
		"sudo -p 'pw: ' id":                         p + " id",
		"/usr/bin/sudo id":                          p + " id",
		"FOO=1 sudo id":                             "FOO=1 " + p + " id",
		"sudo apt update && sudo apt upgrade -y":    p + " apt update && " + p + " apt upgrade -y",
		"if true; then sudo id; fi":                 "if true; then " + p + " id; fi",
		"(sudo id)":                                 "(" + p + " id)",
		"sudo cat /etc/shadow | grep root":          p + " cat /etc/shadow | grep root",
		"sudo ls /root 2>/dev/null":                 p + " ls /root 2>/dev/null",
		"timeout 5 sudo id":                         "timeout 5 " + p + " id",
		"xargs sudo rm < list":                      "xargs " + p + " rm < list",
		"find . -name x -exec sudo rm {} +":         "find . -name x -exec " + p + " rm {} +",
		"ssh host sudo systemctl restart nginx":     p + " -H host systemctl restart nginx",
		"ssh me@web-1 sudo -n apt update":           p + " -H me@web-1 apt update",
		// psudo closes stdin: what the command reads is produced inside it.
		"echo 'a b' | sudo tee -a /etc/hosts": p + ` sh -c 'echo '"'"'a b'"'"' | tee -a /etc/hosts'`,
		"sudo tee /etc/x < local.conf":        p + " sh -c 'tee /etc/x < local.conf'",

		"echo secret | sudo -S id":              "", // a password on stdin
		"sudo -u postgres psql":                 "", // another user
		"sudo -i":                               "",
		"sudo -s":                               "",
		"sudo":                                  "",
		"sudo -v":                               "",
		"sshpass -p pw ssh host":                "",
		"ssh -p 2222 host sudo id":              "", // ssh options
		"ssh host 'sudo systemctl restart x'":   "", // remote shell code
		"ssh host sudo 'id; id'":                "",
		"echo x | ssh host sudo tee /etc/x":     "",
		"echo $HOME | sudo tee /etc/x":          "", // would expand as root
		"cat ~/x | sudo tee /etc/x":             "",
		"sudo tee /etc/x <<'EOF'\nx\nEOF":       "",
		"echo $(sudo id)":                       "",
		"bash -c 'sudo id'":                     "",
		"harness-secrets-sudo-hook/sudo id":     "",
		"python3 - <<'EOF'\nprint('sudo')\nEOF": "",
	} {
		b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "permission_mode": "bypassPermissions",
			"tool_input": map[string]any{"command": command, "description": "d", "timeout": 5}})
		var out bytes.Buffer
		if err := ClaudeCode(bytes.NewReader(b), &out, p); err != nil {
			t.Fatal(err)
		}
		var res struct {
			HookSpecificOutput struct {
				PermissionDecision string
				UpdatedInput       map[string]any
				AdditionalContext  string
			}
		}
		json.Unmarshal(out.Bytes(), &res)
		h := res.HookSpecificOutput
		if want == "" {
			if h.PermissionDecision != "deny" {
				t.Errorf("%q: %s %v, want deny", command, h.PermissionDecision, h.UpdatedInput)
			}
			continue
		}
		if h.PermissionDecision != "allow" || h.UpdatedInput["command"] != want || h.UpdatedInput["description"] != "d" ||
			h.UpdatedInput["timeout"] != 5.0 || !strings.Contains(h.AdditionalContext, want) {
			t.Errorf("%q: %s %q, want %q", command, h.PermissionDecision, h.UpdatedInput["command"], want)
		}
	}
	// Outside bypassPermissions the user is asked, as for sudo itself.
	if got := decide(t, bash("sudo id")); got != "ask" {
		t.Fatalf("default mode: %s, want ask", got)
	}
}

func TestReasonAndFailClosed(t *testing.T) {
	var out bytes.Buffer
	ClaudeCode(strings.NewReader(bash("sudo -i")), &out, "/p/psudo")
	if !strings.Contains(out.String(), "This is not a refusal") || !strings.Contains(out.String(), "/p/psudo -H <ssh-host>") {
		t.Fatalf("reason %s", out.String())
	}
	if decide(t, "not json") != "deny" {
		t.Fatal("unparseable input allowed")
	}
	if decide(t, `{"tool_name":"Read","tool_input":{"file_path":"/etc/sudoers"}}`) != "allow" {
		t.Fatal("non-Bash tool denied")
	}
}

func TestCodexContext(t *testing.T) {
	var out bytes.Buffer
	if err := Codex(strings.NewReader(`{"hook_event_name":"SessionStart"}`), &out, "/c/root-hook/psudo"); err != nil {
		t.Fatal(err)
	}
	var res struct{ HookSpecificOutput map[string]string }
	json.Unmarshal(out.Bytes(), &res)
	ctx := res.HookSpecificOutput["additionalContext"]
	if !strings.Contains(ctx, "/c/root-hook/psudo -H <ssh-host>") || res.HookSpecificOutput["permissionDecision"] != "" {
		t.Fatalf("context %q", out.String())
	}
	out.Reset()
	Codex(strings.NewReader(`{"hook_event_name":"PermissionRequest"}`), &out, "/p")
	if out.Len() != 0 {
		t.Fatal("context emitted for another event")
	}
}
