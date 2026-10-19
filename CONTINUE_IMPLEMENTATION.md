# Continue: fresh Git-push approvals and local Pi testing

## Goal

Require a fresh, one-time human approval for every **statically recognized** `git push` across all Pi projects. Approval must never create session, workspace, global, or learned/model permission. Explicit deny remains a deny.

Preserve the existing sandbox grant system: supported missing path, network, and authentication access must prompt **before** execution, be limited to the current invocation, and never retry a failed command automatically.

## Scope

- Work only in `/home/user/dev/pi-sentinel`.
- Do **not** edit `~/.pi/agent/git/github.com/DxTa/pi-sentinel`; it is the installed checkout, not the development repository.
- Do **not** edit the planner-owned canonical session plan:
  `/home/user/.pi/agent/sessions/--home-user-dev-proj--/00000000-0000-0000-0000-000000000000.plan.md`.
- After code verification, update only the pi-sentinel item in `~/.pi/agent/settings.json` to point to this local checkout.
- No dependency install, commit, push, package update, Pi reload, remote probe, or transport migration.

## Current handoff state

- Checkout is at `5f1e620`.
- Baseline focused tests passed: **80 tests** in `yolo-mode`, `permission-dialog`, `runner`, and forwarding polling suites.
- Existing uncommitted **red tests** are intentional:
  - `src/yolo-mode.test.ts`
  - `src/permission-dialog.test.ts`
  - `src/handlers/gates/runner.test.ts`
- They currently fail because the API/behavior under test does not exist yet.
- Source writes previously failed with `Errno 30: Read-only file system`; acquire normal writable access before the green phase.

## Behavior contract

### Git pushes

Recognize statically readable forms only:

- `git push origin main`
- `git -C repo push origin main`
- `/usr/bin/git push origin main`
- parsed compounds/wrappers: `git status && git push origin main`, `bash -c 'git push origin main'`
- quoted literal command prefixes: `git "push" origin main`, `git pu'sh' origin main`, `"git" "-C" repo "push" origin main`

For those commands:

1. Prompt on every invocation even if a policy, session rule, workspace rule, global rule, history, yolo, or yolo-auto would otherwise allow it.
2. Preserve an explicit `deny`; block without showing approval choices.
3. Show only `Yes`, `No`, and `No, provide reason`.
4. Do not record session/workspace/global permission or yolo-auto learning labels.
5. Block if no prompt path exists.

Do not promise recognition inside arbitrary opaque/dynamically constructed interpreter code.

### Sandbox

`src/index.ts` already preflights supported sandbox network/path/auth needs with `promptSandboxGrant`. Reuse it. Do not add another grant store, host bypass, or automatic retry. Change sandbox code only after a real registered-handler reproduction proves a preflight/visibility mismatch.

## Implementation: red → green slices

### 1. Quoted Git-push matcher

**Red tests already exist:** `src/yolo-mode.test.ts`.

In `src/bash-segments.ts`:

1. Export the existing literal parser as:
   ```ts
   export function bashLiteralWord(word: string | undefined): string | null
   ```
2. Update all current callers, including `bashLiteralWords()` and `shellCode()`. Do not leave the old `literal` name behind.
3. Preserve its rule that expansions/escapes return `null`.

In `src/yolo-mode.ts`:

1. Import `bashLiteralWord`.
2. Extract Git command recognition into:
   ```ts
   function isGitPushWords(words: readonly string[]): boolean
   ```
3. Normalize tokens using `bashLiteralWord(word) ?? word`, then reuse `GIT_VALUE_OPTIONS` and `subcommandIndex`.
   - Only the executable/options/subcommand need to be literal.
   - A dynamic remote/ref after `push` is still valid.
4. Reuse this helper from `isBuiltInAskCommand()`.
5. Export `matchesGitPushCommand(command)`, using existing `bashInnerCommands()` and `bashWords()`.

Run:
```bash
npm test -- --run src/yolo-mode.test.ts
```

### 2. Override allow/session fast paths

**Red test already exists:** `src/handlers/gates/runner.test.ts`.

In `src/handlers/gates/descriptor.ts`, add:
```ts
/** Require interactive one-time approval even when policy or session rules allow. */
freshApproval?: boolean;
```

In `src/handlers/gates/runner.ts`, after resolving `check` and before the session-hit return:
```ts
if (descriptor.freshApproval && check.state !== "deny") {
  check = { ...check, state: "ask" };
}
```

Skip the session-hit fast path when `freshApproval` is true. Keep `applyPermissionGate()` unchanged; it already preserves deny and blocks unavailable confirmation. Fresh descriptors must have no `sessionApproval`, so nothing persists.

Run:
```bash
npm test -- --run src/handlers/gates/runner.test.ts
```

### 3. Dialog and learning suppression

**Red test already exists:** `src/permission-dialog.test.ts`.

In `src/permission-dialog.ts`:

1. Add `allowSession?: boolean` to `RequestPermissionOptions`.
2. Default it to true.
3. Omit the session choice when false.
4. Only return `approved_for_session` if that choice was displayed.

In `src/permission-prompter.ts`:

1. Add `allowSession?: boolean` to `PromptPermissionDetails`.
2. For ordinary prompts, preserve current options shape: `{ allowWorkspace: Boolean(ctx.cwd) }`.
3. For `allowSession === false`, send:
   ```ts
   { allowSession: false, allowWorkspace: false, allowGlobal: false }
   ```
4. Skip `labelEvaluation()` when `details.allowSession === false`.

Run:
```bash
npm test -- --run src/permission-dialog.test.ts src/permission-prompter.test.ts
```

### 4. Forwarding

Files:

- `src/permission-forwarding.ts`
- `src/forwarded-permissions/io.ts`
- `src/forwarded-permissions/polling.ts`
- `src/forwarded-permissions/polling.test.ts`

Add optional `allowSession?: boolean` to the forwarded request. Parse it only if boolean. Carry it from `confirmPermission()` to `waitForForwardedPermissionApproval()`.

When it is false, the parent dialog receives:
```ts
{ allowSession: false, allowWorkspace: false, allowGlobal: false }
```

For ordinary forwarding, retain the current no-options call behavior if possible. Metadata must only **remove** choices; a child cannot gain authority with it.

Add a forwarding regression for `git push` with `forcePromptInYolo: true` and `allowSession: false` that checks the parent dialog options.

Run:
```bash
npm test -- --run src/forwarded-permissions/polling.test.ts
```

### 5. Final tool gate

In `src/handlers/gates/tool.ts`:

1. Import `matchesGitPushCommand`.
2. Recognized Bash pushes set `freshApproval`.
3. Set `sessionApproval` to `undefined` for them.
4. Add `promptDetails.allowSession = false` and `forcePromptInYolo = true`.
5. Put `freshApproval: true` on the descriptor.
6. Preserve ordinary behavior.

### 6. Earlier Bash path/external-directory gates

Review found this important gap: `git -C /outside/repo push …` can prompt at an earlier gate with persistent choices.

In `src/handlers/permission-gate-handler.ts`:

1. Import `matchesGitPushCommand`, `GateDescriptor`, `GateResult`, and `isGateDescriptor`.
2. Compute once from original command:
   ```ts
   const bashCommand = tcc.toolName === "bash"
     ? getNonEmptyString(toRecord(tcc.input).command)
     : null;
   const freshPushApproval = bashCommand !== null
     && matchesGitPushCommand(bashCommand);
   ```
3. Add a small local transformer:
   ```ts
   function requireFreshPushApproval(result: GateResult, isFreshPush: boolean): GateResult
   ```
   For a descriptor, return a copy with `freshApproval: true`, no `sessionApproval`, and prompt details `{ allowSession: false, forcePromptInYolo: true }`.
4. Apply it to `describeBashExternalDirectoryGate()` and `describeBashPathGate()` outputs before `runGateCheck()`.
5. Preserve gate bypasses and pre-resolved deny results.

Add an index-level test in `src/index-yolo-hard-rules.test.ts` that:

- runs `git -C <outside-path> push origin main`;
- checks every approval dialog has only the three once-only answers;
- checks deny blocks without a dialog;
- checks two pushes prompt twice.

## Sandbox evidence gate

Before editing sandbox sources, run:
```bash
npm test -- --run \
  src/index-srt-default-smoke.test.ts \
  src/sandbox/external-path-gate.test.ts \
  src/sandbox/sandbox-visible-paths.test.ts \
  src/sandbox/sandbox-prompt.test.ts
```

If external-path preflight passes, make no sandbox source changes. If it fails, reproduce through the registered handler and compare the visibility matcher with actual SRT mounts. Fix one proven layer only.

## Verification

After all slices:
```bash
npm test -- --run \
  src/yolo-mode.test.ts \
  src/permission-dialog.test.ts \
  src/permission-prompter.test.ts \
  src/handlers/gates/runner.test.ts \
  src/forwarded-permissions/polling.test.ts \
  src/index-yolo-hard-rules.test.ts
npm run check
npm test
git diff --check
git status --short
```

Then:

1. Run `ripwire --quality-delta` and edit-check/affected for touched symbols.
2. Run standards/spec review and fix Critical/Important findings.
3. Do the ponytail lean pass: no dependency, duplicate parser, second grant store, broad bypass, or automatic retry.
4. Re-run all verification after fixes.

If full test/typecheck cannot resolve Pi peers, report exact missing peer errors. Do not install dependencies as a workaround.

## Settings update for local testing

Only after verification, replace exactly one entry in `~/.pi/agent/settings.json`:

```json
"git:github.com/DxTa/pi-sentinel@main"
```

becomes:

```json
"/home/user/dev/pi-sentinel"
```

Do not add a second entry. Do not run `pi-bolt update` for a local source.

Validate:
```bash
python3 - <<'PY'
import json
from pathlib import Path
settings = json.loads(Path.home().joinpath('.pi/agent/settings.json').read_text())
entries = settings['packages']
assert '/home/user/dev/pi-sentinel' in entries
assert 'git:github.com/DxTa/pi-sentinel@main' not in entries
assert sum('pi-sentinel' in item for item in entries) == 1
print('local pi-sentinel package configured once')
PY
```

Start a **new Pi-Bolt session** after this change. Do not assume the live session reloads package code.

## Review findings to keep covered

1. **Critical:** quoted literal pushes must not bypass approval.
2. **Important:** earlier path/external-directory prompts for a push must not offer persistence.
3. **Important:** ordinary prompter option shape must stay unchanged; only one-time requests suppress choices.

## Non-goals

No live push, remote migration, credential change, commit, branch cleanup, package update, new settings flag, second grant cache, broad sandbox bypass, or automatic retry.
