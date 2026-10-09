# Decision Record: Bash decisions use inner commands; opaque code never inherits an allow

**Date**: 2026-10-09
**Status**: accepted
**Decision maker**: (auto-recorded by docs-memory extension)

## Context

Sentinel matched Bash rules, stored approvals, the yolo-auto history key, the workspace cd check and the yolo ask patterns against text that included loop keywords and wrappers. Approving one loop stored `for *`, `do *` and `done`, which then allowed any later loop body. A hidden `rm` after `&&` skipped the built-in ask list. The classifier cuts input at 256 tokens, so a long harmless prefix could hide the real command. The installed model (Patronus-derived `patronus_unified_multitask_v3`, mmBERT-small) exposes 7 logit heads only; its shared 384-d CLS vector is not a graph output.

## Decision

One synchronous, quote-aware `bashInnerCommands` in `src/bash-segments.ts` returns the real inner commands plus `opaque` and `elevated` flags. All five surfaces use it. Keywords, groups and transparent wrappers are removed. `xargs`, `find -exec`, `bash -c '<literal>'` (two levels) and `sudo` are read. Code that cannot be read (eval, source, trap, interpreter -c/-e, bash without a script, `$cmd`, case, functions, PATH/LD_*/IFS prefixes, unknown wrapper options) is opaque: rules never allow it, no approval pattern is stored, history gets no key, and the model may still allow it at the normal thresholds. `sudo` always prompts. Deny rules and ask patterns also match the wrapper text. The model classifies the whole command and each inner command; allow needs every input to allow; more than 8 inner commands or one over 200 bytes (a token is never shorter than one byte, so the cap keeps each input inside the 256-token window; an exact token-overflow flag from the worker is a possible follow-up) prompts; history may convert only one low-confidence input. Telemetry adds counts and an index, never text.

## Alternatives considered

Tree-sitter parsing: rejected because the public `checkPermission` is synchronous and the existing parser is async. Synthetic "intent" annotations for the model: rejected because the classifier was never trained on that format. Embedding similarity now: deferred. A second model is unnecessary because the existing model already computes a CLS vector for every head, but exposing it needs a graph edit and a new pinned file, and only 1 plausible human denial exists to set a threshold. Migrating stale rules: rejected; README gives a one-line check.

## Consequences

More prompts for compound commands that hide ask-list commands in yolo mode, and up to 9 worker calls per compound command. Old history keys stop matching and age out within 30 days. Follow-ups: (1) shadow-only embedding similarity by exposing `/model/Gather_output_0` through a derived ONNX file; it must never allow; (2) the permission dialog still offers session, workspace and global options for opaque code even though nothing is stored; hide them; (3) the prompter's no-evaluator fallback path classifies the whole text only and is dead in production; remove it; (4) the calibration report does not yet slice by `unitCount` or `opaque`.

## Related

- <!-- add links to relevant docs or code -->
