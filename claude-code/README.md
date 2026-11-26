# Claude Code

Part of [Harness Secrets Sudo Hook](../README.md). For Codex, see the [Codex guide](../codex/README.md).

## Install

```sh
psudo --install=claude-code      # from a release archive: ./psudo --install=claude-code
# or from a source checkout:
make install-claude-code
```

The installer:

- copies the binary to `~/.claude/hooks/psudo`;
- registers `"$HOME"/.claude/hooks/psudo --hook=claude-code` as a `PreToolUse`
  hook for `Bash` in `~/.claude/settings.json`. Other settings and hooks are
  kept in order, and the first run backs the file up to `settings.json.bak`;
- registers `--hook=claude-code-session-start` as a `SessionStart` hook. It
  tells each session about `psudo` from the start, including `psudo -H` for
  remote hosts. The guard alone only reacts to commands that contain `sudo`.
  Without this hook, a session asked for root on a host ran `ssh root@host`
  and never used `psudo`;
- registers `--hook=claude-code-session-end` as a `SessionEnd` hook. It forgets
  the secrets you chose to keep "for this session only" when the session ends
  (also on `/clear`);
- creates `~/.config/harness-root-hook/config.json` if it is missing;
- on macOS, registers the `com.harness-root-hook.claude-code.reaper` launchd
  task, which deletes expired Keychain entries every five minutes without
  reading the password;
- removes the previous shell/Python integration (`sudo-check.sh`, `askpass.sh`,
  `reaper.sh`, `harness_cache.py`) and its old cache entries. A cache entry
  created by the previous version keeps working.

Restart Claude Code afterwards. Linux needs `secret-tool`
(`sudo apt install libsecret-tools zenity` on Ubuntu) and a running Secret Service
provider.

## What the hook does

The hook **converts** a Bash command's `sudo` to `psudo` and lets it go ahead,
because a harness reads a denied command as a stop. It tells the model what ran.
In a session that bypasses permissions the converted command runs at once; in
any other mode Claude Code's permission prompt shows you the converted command.
What it cannot convert exactly, and `sshpass`, it denies with a message that says
the task goes on through psudo and gives the form to use.

The hook is best effort. A command that gets past it still fails safely,
because sudo without a terminal or password cannot authenticate.

| Command | Decision |
| --- | --- |
| `sudo apt install x` | runs `psudo apt install x` |
| `ssh host sudo systemctl restart nginx` | runs `psudo -H host systemctl restart nginx` |
| `echo x \| sudo tee -a /etc/hosts` | runs `psudo sh -c 'echo x \| tee -a /etc/hosts'` |
| `psudo ls && sudo rm x` | runs `psudo ls && psudo rm x` |
| `echo … \| sudo -S …` | deny |
| `sudo -u postgres psql`, `sudo -i` | deny |
| `bash -c 'sudo id'` | deny |
| `sshpass -p … ssh host` | deny |
| `psudo apt install x` | allow |
| `cat /etc/sudoers` | allow |

To avoid wasted turns, you can add one line to your `CLAUDE.md`: *"Privileged
commands go through `~/.claude/hooks/psudo [-H host] cmd`; never request, echo or
store a password."*

## Verify

Ask Claude Code to run each of these:

1. `sudo id -u`: converted, it runs as `~/.claude/hooks/psudo id -u`.
2. `~/.claude/hooks/psudo id -u`: one dialog naming *this computer* and `id -u`, then `0`.
   With the cache off (the default) every run shows the dialog.
3. `~/.claude/hooks/psudo -H <your-ssh-alias> id -u`: a dialog naming the host, then `0`.
   Every remote run prompts.
4. Cancel a dialog: exit 251. Enter a wrong password: exit 252, and the command does not run.

Neither `ps`, your shell history, nor the transcript should contain the password.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `sudo` still runs or fails with "a terminal is required" | Restart Claude Code; check `/hooks` lists `psudo --hook=claude-code`. |
| Exit 250 | No desktop dialog (Linux: `DISPLAY`/`WAYLAND_DISPLAY` and zenity/kdialog), invalid `config.json`, or a locked or missing credential store. |
| Exit 255 before any dialog | The host is unreachable, or the SSH login failed. Check `ssh <host> true` in a terminal. A host that needs a code or password gets an **SSH login** dialog; a wrong code or a cancel also exits 255. |
| Exit 252 on a remote host that should work | The remote user must be allowed to use sudo, `requiretty` must be off, and the login shell must be POSIX. `NO SUDO` means the host has no sudo (Proxmox, for example): log in as root with `-H root@<host>`. |
| macOS: launchd task status | `launchctl print "gui/$(id -u)/com.harness-root-hook.claude-code.reaper"` |

## Uninstall

```sh
~/.claude/hooks/psudo --uninstall=claude-code
```

This removes the hook registration, the cached password, the launchd task and the
binary. On macOS it also removes the test app `/Applications/psudo.app`, if one
is installed and Codex no longer uses psudo either. The shared `config.json` stays for Codex or a future install.
