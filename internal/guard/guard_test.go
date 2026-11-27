package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
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
		// Data piped into a shell is matched as plain text: only the exact
		// project name is skipped there.
		"cat harness-secrets-sudo-hook sudo | sh": "deny",
		"cat sudo-harness-secrets-sudo-hook | sh": "deny",
		"cat harness-secrets-sudo-hook-sudo | sh": "deny",
		"cat harness-secrets-sudo -hook | sh":     "deny",
		"cat my-sudo-notes | sh":                  "deny",
		"cat harness-secrets-sudo-hook | sh":      "allow",

		// sudo that only names a file or a package is data: the program run is
		// not sudo (regression, fermi-android-dev: reading which sudo a host has).
		"ls my-sudo-notes":                                                  "allow",
		"ls harness-secrets-sudo-hook sudo":                                 "allow",
		"readlink -f /usr/bin/sudo":                                         "allow",
		"ls -l /usr/bin/sudo* /usr/lib/cargo/bin/":                          "allow",
		"dpkg-query -W -f '${Package} ${Version}\\n' sudo sudo-rs":          "allow",
		"update-alternatives --display sudo":                                "allow",
		"apt-cache policy sudo":                                             "allow",
		"whereis sudo":                                                      "allow",
		"find / -name sudo -type f":                                         "allow",
		"stat /etc/sudoers.d /usr/bin/sudo":                                 "allow",
		"ssh h 'id; readlink -f /usr/bin/sudo; dpkg-query -W sudo sudo-rs'": "allow",
		"gh api 'repos/o/sudo-rs/git/trees/v0.2.13?recursive=1' --jq '.tree[].path' | grep -E 'src/sudo/pipeline'": "allow",
		"gh api repos/o/sudo-rs/contents/src/sudo/pam.rs?ref=v0.2.13 --jq .content | base64 -d":                    "allow",
		"curl -sL https://github.com/o/sudo-rs/archive/v1.tar.gz -o sudo-rs.tgz":                                   "allow",
		// sudo written as something to run, or as the program a value sets, is not.
		"sudo-rs id":                                  "deny",
		"/usr/bin/sudo-ws id":                         "deny",
		"timeout 5 sudo-rs id":                        "deny",
		"noglob sudo id":                              "deny",
		"coproc sudo id":                              "deny",
		"repeat 2 sudo id":                            "deny",
		"mytool sudo id":                              "deny",
		"tmux new-session -d 'sudo id'":               "deny",
		"nix-shell --run 'sudo id'":                   "deny",
		"alias x='sudo id'":                           "deny",
		"alias x=sudo":                                "deny",
		"make SUDO=/usr/bin/sudo install":             "deny",
		"git -c core.pager=sudo log":                  "deny",
		"git config core.pager sudo":                  "deny",
		"gh config set pager sudo":                    "deny",
		"find . -exec sudo-rs rm {} +":                "deny",
		"find / -name sudo -exec sudo id \\;":         "deny",
		"ssh h 'dpkg-query -W sudo; sudo id'":         "deny",
		"ssh -o RemoteCommand='sudo id' h":            "deny",
		"ssh h /usr/bin/su?o id":                      "deny",
		"eval sudo id":                                "deny",
		"mytool --exec=sudo":                          "deny",
		"mytool s{u,}do id":                           "deny",
		"gh myext sudo id":                            "deny",
		"gh extension exec x sudo":                    "deny",
		"gh repo clone o/r -- --upload-pack='sudo x'": "deny",
		"echo 'sudo id' | python3 | sh":               "deny",
		"cat notes-sudo | ssh h sh":                   "deny",
		// A program taken from find's results or from xargs' input can be a
		// sudo that was only named as data (found by security review).
		"find /usr/bin -name sudo -exec {} id \\;":         "deny",
		"find /usr/bin -name 'su?o' -exec {} id \\;":       "deny",
		"find /usr/bin -iname SUDO -exec {} id \\;":        "deny",
		"find /usr/bin -perm -4000 -exec {} id \\;":        "deny",
		"find / -path '*/bin/*' -name x -exec {} \\;":      "deny",
		"find /usr/bin -name sudo | xargs -I{} {} id":      "deny",
		"readlink -f /usr/bin/sudo | xargs -I% % id":       "deny",
		"readlink -f /usr/bin/sudo | xargs -i{} {} id":     "deny",
		"echo /usr/bin/sudo | parallel {} id":              "deny",
		"parallel {} id ::: /usr/bin/sudo":                 "deny",
		"ssh h 'S=$(which sudo); $S id'":                   "deny",
		"ssh h 'S=/usr/bin/sudo; $S id'":                   "deny",
		"ssh h 'which sudo | xargs -I{} {} id'":            "deny",
		"ssh h 'find /usr/bin -name sudo -exec {} id \\;'": "deny",
		"find . -name '*.sh' -exec {} \\;":                 "allow",
		"find /usr/bin -name sudo -exec ls -l {} +":        "allow",
		"ls *.txt | xargs -I{} cp {} /tmp":                 "allow",
		"ssh h 'V=/opt/tool; $V --version'":                "allow",
		// What reads a shell's or ssh's output is not fed to it.
		"ssh h 'cat /etc/sudoers.d/90-cloud-init-users' | grep sudo": "allow",
		"ssh h 'readlink -f /usr/bin/sudo' | head":                   "allow",
		"echo 'readlink -f /usr/bin/sudo' | ssh h":                   "allow",
		"eval 'readlink -f /usr/bin/sudo'":                           "allow",
		"ssh -o RemoteCommand='readlink /usr/bin/sudo' h":            "allow",
		// gh's own commands take prose and paths.
		"gh pr create --title 'Convert sudo to psudo' --body 'sudo-rs hosts run without a dialog'": "allow",
		"gh issue comment 3 -b 'run sudo id through psudo'":                                        "allow",
		"gh codespace ssh -- sudo id":                                                              "allow",

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
		"git commit -am 'Explain sudo'":              "allow", // found by the regression run
		"git commit -qm 'Explain sudo'":              "allow",
		"git commit -Cm 'sudo id'":                   "deny", // -C takes "m" as its value
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
	// Only the folder computed, in double quotes: the program is known, and
	// judged by its name. Unquoted, the shell splits and globs the value, so
	// the program could be anything.
	for command, want := range map[string]string{
		`for h in bohr maxwell; do ./"$h"/fleet-ssh 'qm list'; done`: "allow",
		`"$dir"/fleet-ssh 'qm list'`:                                 "allow",
		`"${HOME}"/bin/tool --flag`:                                  "allow",
		`"$HOME/bin"/tool --flag`:                                    "allow",
		`'/opt/my dir'/"$v"/tool x`:                                  "allow",
		"for h in bohr maxwell; do ./$h/fleet-ssh 'qm list'; done":   "deny",
		"${HOME}/bin/tool --flag":                                    "deny",
		`h=$(printf '\163udo id; '); $h/fleet-ssh x`:                 "deny",
		`"$(pick)"/tool x`:                                           "deny",
		`"${x:-$(pick)}"/tool x`:                                     "deny",
		`"$@"/tool x`:                                                "deny",
		`"$h/"tool x`:                                                "deny",
		`"$h"/*/tool x`:                                              "deny",
		`"${x@P}"/tool x`:                                            "deny",
		`"${!x}"/tool x`:                                             "deny",
		`"${x:-a}"/tool x`:                                           "deny",
		`"${x[1]}"/tool x`:                                           "deny",
		`"${}"/tool x`:                                               "deny",
		`"$x[1]"/tool x`:                                             "deny",
		`"$x:h"/tool x`:                                              "deny",
		`"$x"[ab]/tool x`:                                            "deny",
		`"$x(1)"/tool x`:                                             "deny",
		`"$x"/"$y"/tool x`:                                           "allow",
		`"$HOME"/.local/bin/tool x`:                                  "allow",
		"$d/sudo id":                                                 "deny",
		"$d/sshpass -p x ssh h":                                      "deny",
		"$d/env sudo id":                                             "deny",
		"$d/sh -c 'sudo id'":                                         "deny",
		"$d/fleet-ssh 'sudo id'":                                     "deny",
		"$d/security find-generic-password -w -s x":                  "deny",
		"$(sudo id)/fleet-ssh x":                                     "deny",
		"${p:-/bin/sh} -c x":                                         "deny",
		"$(echo a/b) x":                                              "deny",
		"`pick`/tool x":                                              "deny",
		"$d/$prog x":                                                 "deny",
		"$d/${x}tool":                                                "deny",
	} {
		if got := verdictOf(command); got != want {
			t.Errorf("%q: %s, want %s", command, got, want)
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

		// Found by the regression run: through a wrapper, a sudo that runs
		// on an SSH host became this computer's psudo path on that host, and
		// watch would run psudo again every two seconds.
		"timeout 20 ssh host sudo id -u":                 "",
		"nohup ssh host sudo id -u":                      "",
		"env FOO=1 ssh host sudo id -u":                  "",
		"xargs -n1 ssh host sudo id < hosts":             "",
		"find . -maxdepth 0 -exec ssh host sudo id \\;":  "",
		"watch sudo id":                                  "",
		"builtin exec sudo id":                           "builtin exec " + p + " id",
		"timeout -s KILL 20 sudo id":                     "timeout -s KILL 20 " + p + " id",
		"env -u X FOO=1 sudo id":                         "env -u X FOO=1 " + p + " id",
		"find . -exec sudo rm {} \\; -exec sudo ls {} +": "find . -exec " + p + " rm {} \\; -exec " + p + " ls {} +",
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
	// Found by the regression run: denied with the sudo reason, sshpass made
	// models answer a password-login task with a root command.
	for command, own := range map[string]bool{
		"sshpass -p pw ssh host id":             true,
		"timeout 5 sshpass -f f ssh host":       true,
		"sshpass -p pw ssh host sudo id":        false,
		"sudo -i":                               false,
		"cd harness-secrets-sudo-hook; sshpass": true,
	} {
		out.Reset()
		ClaudeCode(strings.NewReader(bash(command)), &out, "/p/psudo")
		if got := strings.Contains(out.String(), "sshpass puts an SSH password"); got != own || !strings.Contains(out.String(), `"deny"`) {
			t.Errorf("%q: sshpass reason %v, want %v: %s", command, got, own, out.String())
		}
	}
	out.Reset()
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

// Found by the regression run (docs/regression.md): each "deny" below ran a
// fake sudo under bash or under zsh set up as Claude Code runs it, while the
// guard allowed it. The "allow" rows are ordinary commands next to them.
func TestParserDifferentials(t *testing.T) {
	for command, want := range map[string]string{
		// Brace expansion and globs spell the program.
		"{sud,ech}o id":                                 "deny",
		"s{u,}do id":                                    "deny",
		"/usr/bin/su?o id":                              "deny",
		"/usr/bin/s[u]do id":                            "deny",
		"/usr/bin/sud* id":                              "deny",
		`"/usr/bin/"su?o id`:                            "deny",
		"command /usr/bin/su?o id":                      "deny",
		"exec -a x /usr/bin/su?o id":                    "deny",
		"repeat 1 /usr/bin/su?o id":                     "deny",
		"timeout -s KILL 5 /usr/bin/su?o id":            "deny",
		"find . -maxdepth 0 -exec /usr/bin/su?o id \\;": "deny",
		"./*/tool x":                                    "deny",
		"cp a.txt{,.bak}":                               "allow",
		"mkdir -p x/{a,b}":                              "allow",
		"echo {1..3}":                                   "allow",
		"ls *.txt":                                      "allow",
		"rm -f s*":                                      "allow",
		`for f in internal/*/; do echo "$f"; done`:      "allow",
		"ls /usr/bin/su?o":                              "allow",
		// A lone [ is the test command, not a pattern.
		"{ [ -d .git ] || git init -q .; }": "allow",
		"[[ -f x ]] && echo y":              "allow",
		`[ -n "$x" ] && echo y`:             "allow",
		"[x]y":                              "deny",

		// Code for a shell is parsed, not only matched as text: quotes and
		// backslashes are removed there, and computed names are computed.
		`sh -c 's\udo id'`:                               "deny",
		`bash -c "s''udo id"`:                            "deny",
		`eval 's\udo id'`:                                "deny",
		`ssh host 's\udo id'`:                            "deny",
		`git -c alias.x='!s\udo id' x`:                   "deny",
		`env -S 's\udo id'`:                              "deny",
		`echo 's\udo id' | sh`:                           "deny",
		`sh <<< 's\udo id'`:                              "deny",
		"sh -c '{sud,ech}o id'":                          "deny",
		`a=su; b=do; sh -c "$a$b id"`:                    "deny",
		"sh -c 'a=su;b=do;$a$b id'":                      "deny",
		"a=su; b=do; eval '$a$b id'":                     "deny",
		"a=su;b=do; command eval '$a$b id'":              "deny",
		"a=su;b=do; sh -ec '$a$b id'":                    "deny",
		"a=su;b=do; bash -o pipefail -c '$a$b id'":       "deny",
		"ssh -oProxyCommand='a=su;b=do;$a$b nc %h %p' h": "deny",

		// Code that runs on an SSH host: sudo spelled in any form is denied,
		// a computed name is not (the host's shell may be PowerShell, and
		// sudo there has no terminal and no password). Found by replaying
		// real commands from Claude Code transcripts.
		"a=su;b=do; ssh host \"$a$b id\"":                                   "allow",
		`ssh win '$ProgressPreference="SilentlyContinue"; powershell -c x'`: "allow",
		"ssh host 'T=/opt/tool; $T --help'":                                 "allow",
		`s() { ssh host "$@"; }; s 'ls /'`:                                  "allow",
		`echo '$a$b id' | ssh host`:                                         "allow",
		"ssh host <<'EOF'\nV=/x/py; $V -c 1\nEOF":                           "allow",
		"ssh host <<'EOF'\ns\\udo id\nEOF":                                  "deny",

		// A value written in the same command is judged where it is used.
		`CMD='qm list; pct list'; ssh host "$CMD"`:                "allow",
		`CMD='sudo reboot'; ssh host "$CMD"`:                      "deny",
		`CMD='s\udo reboot'; ssh host "$CMD"`:                     "deny",
		`J='ssh -W %h:%p jump'; ssh -o ProxyCommand="$J" h true`:  "allow",
		`J='a=su;b=do;$a$b nc %h %p'; ssh -o ProxyCommand="$J" h`: "deny",
		`ssh -o ProxyCommand="$J" h true`:                         "deny",
		`X='cd /tmp && ls'; sh -c "$X"`:                           "allow",
		`X='a=su;b=do;$a$b id'; sh -c "$X"`:                       "deny",
		`X=$(pick); sh -c "$X"`:                                   "deny",
		`X='ls'; X="$Y"; sh -c "$X"`:                              "deny",
		`export X='ls'; eval "$X"`:                                "deny", // eval and export may set variables: X is not followed
		`X='sudo id'; eval '$X'`:                                  "deny",
		`X='ls'; sh -c "${X}"`:                                    "allow",

		// Only plain assignments are followed. A variable set any other way
		// after a literal one is unknown, so the code it holds is computed.
		`X=true; read X; sh -c "$X"`:                "deny",
		`X=true; read X; eval "$X"`:                 "deny",
		`X=true; printf -v X '%s' "$Y"; sh -c "$X"`: "deny",
		`X=true; declare -n X=Y; sh -c "$X"`:        "deny",
		`X=true; local -n X=Y; sh -c "$X"`:          "deny",
		`X=true; declare -i X=1; sh -c "$X"`:        "deny",
		`X=true; let X=1; sh -c "$X"`:               "deny",
		`X=true; getopts a X; sh -c "$X"`:           "deny",
		`X=true; mapfile -t X < f; sh -c "$X"`:      "deny",
		`X=true; for X in a b; do sh -c "$X"; done`: "deny",
		`X=true; (( X = 1 )); sh -c "$X"`:           "deny",
		// Variables set without their name being written, and names the
		// shell sets itself, are never followed.
		`REPLY=true; read; sh -c "$REPLY"`:                "deny",
		`OPTARG=true; getopts a: o -a x; sh -c "$OPTARG"`: "deny",
		`MAPFILE=true; mapfile < f; sh -c "$MAPFILE"`:     "deny",
		`_=true; echo x; sh -c "$_"`:                      "deny",
		`X=true; N=Y; printf -v "$N" x; sh -c "$X"`:       "deny",
		`X=true; read N < f; declare "$N=1"; sh -c "$X"`:  "deny",
		`X=true; source ./f; sh -c "$X"`:                  "deny",
		`X=true; . ./f; sh -c "$X"`:                       "deny",
		`X=true; eval "$Y"; sh -c "$X"`:                   "deny",
		`X=true; : ${(P)N::=v}; sh -c "$X"`:               "deny",
		`X=true; command read N; sh -c "$X"`:              "deny",
		`X=true; f() { read; }; f; sh -c "$X"`:            "deny",
		// A variable that is not followed is still judged by every literal
		// value it is given.
		`CMD='sudo reboot'; printf x; ssh host "$CMD"`: "deny",
		`CMD='qm list'; printf x; ssh host "$CMD"`:     "allow",
		`CMD='sudo reboot'; read CMD; ssh host "$CMD"`: "deny",
		// Every builtin may set a variable, except a few quiet ones.
		`X=true; set -A X a; sh -c "$X"`:       "deny",
		`X=true; zformat -f X a; sh -c "$X"`:   "deny",
		`X=true; integer X; sh -c "$X"`:        "deny",
		`X=true; compgen -v -X x; sh -c "$X"`:  "deny",
		`X='ls'; cd /tmp; echo hi; sh -c "$X"`: "allow",
		// Too many values: each one is still judged on its own.
		`C='sudo reboot'; C=v0; C=v1; C=v2; C=v3; C=v4; C=v5; C=v6; C=v7; C=v8; C=v9; C=v10; C=v11; C=v12; C=v13; C=v14; C=v15; C=v16; C=v17; C=v18; C=v19; ssh host "$C" "$C"`: "deny",
		`C='qm list'; C=v0; C=v1; C=v2; C=v3; C=v4; C=v5; C=v6; C=v7; C=v8; C=v9; C=v10; C=v11; C=v12; C=v13; C=v14; C=v15; C=v16; C=v17; C=v18; C=v19; ssh host "$C" "$C"`:     "deny",
		`X='cd /tmp && ls'; Y='pwd'; sh -c "$X"; sh -c "$Y"`: "allow",
		`X=true; IFS= read -r X < f; ssh host "$X"`:          "allow",

		// Found by the same replay: case patterns and env assignments.
		`for f in *; do case "$f" in *.md|*.txt|config*) echo "$f";; *) ;; esac; done`: "allow",
		"env -i HOME=$HOME bash -lc 'echo $PATH'":                                      "allow",
		"env -i PS4='$(a=su;b=do;$a$b id)' bash -xc true":                              "deny",
		"a=su;b=do; trap '$a$b id' EXIT":                                               "deny",
		"a=su;b=do; trap -- '$a$b id' EXIT":                                            "deny",
		"a=su;b=do; watch -n1 '$a$b id'":                                               "deny",
		"PS4='$(a=su;b=do;$a$b id)' bash -xc true":                                     "deny",
		"echo 'a=su;b=do;$a$b id' | bash":                                              "deny",
		"cat <<'EOF' | sh\na=su;b=do;$a$b id\nEOF":                                     "deny",
		"bash <<'EOF'\na=su;b=do;$a$b id\nEOF":                                         "deny",
		"bash /dev/stdin <<'EOF'\na=su;b=do;$a$b id\nEOF":                              "deny",
		"source /dev/stdin <<<'a=su;b=do;$a$b id'":                                     "deny",
		". <(echo 'a=su;b=do;$a$b id')":                                                "deny",
		`a=su b=do; echo "$a$b id" | xargs -I{} sh -c '{}'`:                            "deny",
		"cat <(sudo id)":                                                  "deny",
		"eval '$(ssh-agent -s)'":                                          "deny",
		`eval "$(ssh-agent -s)"`:                                          "allow",
		"bash -c 'echo $HOME'":                                            "allow",
		`bash -c 'echo "$1"' _ "$(id)"`:                                   "allow",
		"ssh host 'echo $HOME; uname -a'":                                 "allow",
		"ssh host 'for h in a b; do echo $h; done'":                       "allow",
		"sh -c 'cd /tmp && ls'":                                           "allow",
		`trap 'rm -f "$tmp"' EXIT`:                                        "allow",
		"PS4='+ ' bash -xc 'echo hi'":                                     "allow",
		"curl -fsSL https://example.com/install.sh | sh":                  "allow",
		`echo "$data" | python3 -c 'import sys; print(sys.stdin.read())'`: "allow",
		"diff <(ls a) <(ls b)":                                            "allow",

		// A wrapper's values come before the program; unquoted, bash splits
		// them, so a computed one can be the program.
		"S=sudo; timeout 5 $S id":                      "deny",
		"S=/usr/bin/sudo; nice -n 5 $S id":             "deny",
		"a=su;b=do; xargs -n 1 $a$b < /dev/null":       "deny",
		"x=su; find . -maxdepth 0 -exec ${x}do id \\;": "deny",
		`find . -maxdepth 0 -exec "$x" \;`:             "deny",
		"timeout $T id":                                "deny",
		`timeout "$T" id`:                              "allow",
		`nice -n "$N" make`:                            "allow",
		`find "$dir" -type f`:                          "allow",
		"find . -name '*.go' -exec grep -l foo {} +":   "allow",
		`find . -execdir ./"$h"/tool {} +`:             "allow",
		`timeout 10 curl -s "$url"`:                    "allow",
		`xargs -I{} cp {} "$dest" < list`:              "allow",
		"xargs -n 1 -P 4 curl -s < urls":               "allow",
		"timeout 600 make -C build all":                "allow",

		// zsh's (e) flag and bash's @P run the substitutions in a value; a
		// ${…} whose end bash and zsh read differently is not parsed.
		"x='$(a=su;b=do;$a$b id)'; echo ${(e)x}":     "deny",
		`x='$(a=su;b=do;$a$b id)'; echo "${x@P}"`:    "deny",
		"echo ${x:-$(echo }; a=su;b=do;$a$b id)}":    "deny",
		`echo "${x:-'}'}"; a=su;b=do;$a$b id`:        "deny",
		`echo "${XDG_CONFIG_HOME:-${HOME}/.config}"`: "allow",
	} {
		if got := verdictOf(command); got != want {
			t.Errorf("%q: %s, want %s", command, got, want)
		}
	}
}

// Code built from a variable with more values than the guard checks is
// refused with its own reason, on SSH hosts too, where a computed name is
// otherwise allowed.
func TestTooManyValuesFailsClosed(t *testing.T) {
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, fmt.Sprintf("C=v%d", i))
	}
	for _, command := range []string{
		strings.Join(many, "; ") + `; ssh host "$C" "$C"`,
		strings.Join(many, "; ") + `; eval "$C" "$C"`,
	} {
		var out bytes.Buffer
		if err := ClaudeCode(strings.NewReader(bash(command)), &out, "/home/u/.claude/hooks/psudo"); err != nil {
			t.Fatal(err)
		}
		var res struct{ HookSpecificOutput map[string]any }
		json.Unmarshal(out.Bytes(), &res)
		if r, _ := res.HookSpecificOutput["permissionDecisionReason"].(string); r != TooManyReason {
			t.Errorf("%q: reason %q, want the too-many-values reason", command, r)
		}
	}
	// Under the cap nothing changes.
	if got := decide(t, bash(`C=a; C=b; ssh host "$C"`)); got != "allow" {
		t.Errorf("two values: %s", got)
	}
}
