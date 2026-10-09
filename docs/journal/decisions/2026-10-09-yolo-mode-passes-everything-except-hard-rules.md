# Decision Record: yolo mode passes everything except hard rules

**Date**: 2026-10-09
**Status**: accepted
**Decision maker**: (auto-recorded by docs-memory extension)

## Context

Classic yolo still prompted for many commands: the built-in ask list had 24 entries (docker, aws, gh, scp, git pull and others), external write/edit and non-read-only external Bash forced a prompt, and the bundled write/edit deny outside the workspace stayed in force. There was no hard deny for system-path writes in yolo. The user wants yolo to let everything through except rm, a few remote commands, and writes to forbidden system and credential paths.

## Decision

In classic yolo mode: (1) deny with no prompt any write/edit tool call or readable Bash write (redirects, cp, mv, ln, install, rm, touch, mkdir, tee, truncate, chmod, chown, dd of=, sed -i, curl -o, wget -O) whose target is in a forbidden path: /etc, /System, /Library, /usr except /usr/local, /bin, /sbin, /private/etc, /var except /var/folders and /var/tmp, ~/.ssh, ~/.aws, ~/.gnupg, including symlinks into them; (2) built-in ask list shrinks to rm, ssh, git push and kubectl write verbs (apply, create, delete, edit, patch, replace, set, scale, rollout, drain, cordon, taint, label, annotate), matched against inner commands; (3) external-directory gates stop forcing a prompt; (4) the bundled write/edit deny is relaxed for any path. User deny rules and .env protection stay. yolo-auto is unchanged.

## Alternatives considered

Add a new forcePromptInYoloAuto flag: rejected, because the flag only affects classic yolo (yolo-auto prompts external paths anyway as not workspace-local) and adding a field means changing the forwarding code in 4 files. Deny both rm and forbidden writes: rejected, rm is sometimes wanted. Keep ~/Library and all of /private/var and /tmp forbidden: rejected, tools and macOS write temp and cache files there. Block via the SRT sandbox only: rejected, the sandbox is optional and does not cover host-bypassed commands.

## Consequences

yolo users get far fewer prompts, including docker, aws, gh, scp, rsync, terraform, git pull/clone/fetch and writes outside the workspace. Hard rules: writes to forbidden paths are denied for write/edit and readable Bash (redirects and a verb list); eval and interpreter code pass, so the sandbox is the backstop. rm, ssh, git push and kubectl write verbs still prompt. yolo-auto is unchanged. Follow-ups: a user-editable forbidden-path list in config; apply forbidden-path deny to yolo-auto; extend the verb list (tar -C, unzip -d, git clone DEST).

## Related

- <!-- add links to relevant docs or code -->

## Update after review

- The ask list is a command-aware classifier (executable basename plus subcommand), not wildcard patterns: it catches `/bin/rm`, tab spacing, `git -C r push`, and `kubectl --as x delete`, and ignores `git log --grep push`. User patterns still use wildcards.
- Forced prompts for external write/edit and external Bash, and the legacy hard block on external Bash mutations, are skipped only when the tool call context mode is classic `yolo`. `manual` and `yolo-auto` keep them, which keeps forwarded subagent requests unchanged.
- Network `ask` verdicts are auto-approved in classic `yolo`; explicit denied domains still block.
- Path checks resolve symlinks component by component, so `link/../etc` is caught.
- Known limits: a `cd` inside a subshell can cause a false deny of a later relative write; `kubectl exec`, `tar -C`, `unzip -d`, `git clone <dir>` are not covered.
