# Decision Record: Replace Patronus Ark with direct Apache-2.0 ONNX models

**Date**: 2026-09-29
**Status**: accepted
**Decision maker**: (auto-recorded by docs-memory extension)

## Context

The YoloAuto classifier depended on patronus-ark (GPL-3.0) and on the `l2/` NTDB packages in the Hugging Face repos (GPL-3.0 with a commercial dual license). pi-sentinel is MIT, and the user wants to avoid licence-protected paths so the extension installs and works without extra steps. The ONNX transformer weights in the `patronus-studio` Hugging Face repos are Apache-2.0 and not gated.

## Decision

Remove Ark and the Python worker. Run `patronus-studio/lion-warden-ai-security-classifier` (or its `-edge` variant, chosen by size and latency) in Node with onnxruntime-node and the transformers.js tokenizer. Download the model on first use at a pinned revision, verified by sha256. Use all seven heads: `threat`, `tool_class`, `tool_action`, and `tool_tags` drive permission decisions; `injection` checks untrusted content; `sensitive_document` supports DLP on external sinks; `routing` is logged only. Existing deterministic Sentinel gates replace Ark's L1 rules. The model may only auto-allow; uncertainty or failure falls back to prompting. Never use `l2/` assets.

## Alternatives considered

Bootstrapping Ark into a private virtual environment was rejected because of GPL-3.0 and because this host's default Python is 3.9, below Ark's 3.11 minimum. Vendoring Ark was rejected because it would require relicensing the extension as GPL. Running separate specialist models (wolf, husky, orca, and panther) was rejected for now: Lion Warden covers the same label sets in one forward pass, and specialists can be added later if evaluation shows gaps. GLiNER PII extraction was deferred as a separate DLP feature.

## Consequences

The extension loses Ark's L2 cascade, so every evaluation runs a transformer forward pass. Results should be cached by input hash. Decision thresholds are not yet calibrated and need a small labelled evaluation set before auto-allow is enabled. The change adds npm dependencies onnxruntime-node and @huggingface/transformers.

## Related

- <!-- add links to relevant docs or code -->

## Implementation decisions (D5–D14)

- **D5 — Candidate input:** workspace-local read/list uses tool and relative path; write/edit adds at most 800 content characters; Bash is eligible only when SRT-sandboxed and permission state is `ask`. Outside-workspace paths and network operations prompt. Classifier text stays on the local worker socket.
- **D6 — Hard rule:** system roots `/etc`, `/System`, `/Library`, `/usr`, `/bin`, `/sbin`, `/private`, and `~/Library` never auto-allow; Bash checks extracted paths before model decisions.
- **D7 — Worker lifecycle:** one detached Node worker serves protocol v2; handshake includes build ID; extension shutdown closes only client; stale-build mismatch shuts down and replaces worker. Worker stdout/stderr use owner-only log.
- **D8 — Assets:** pinned revision, resumable downloads, SHA-256 verification, and single-flight locking.
- **D9 — Legacy config:** strip `yoloAutoMaxLevel` and emit one deduplicated warning.
- **D10 — Fixed allow policy:** all gates must pass: threat argmax benign ≥0.90; injection <0.10; sensitive-source and external-sink tags <0.5; tool action matches operation; exec requires Bash; secrets/infra/system classes prompt. Malformed or tied output prompts. Sensitive-document and routing heads are logged only.
- **D11 — Test seams:** pure policy and sensitive-path checks, fake classifier for worker/protocol tests, injected downloader fetch, and opt-in real-model smoke.
- **D12 — Calibration record:** store evaluation ID, timestamp, model revision, tool/operation, input length/hash/truncation, all head vectors, decision/reason, hard-rule/audit flags, and latency. Never store raw text.
- **D13 — Human labels:** 5% of would-allow decisions prompt as audit. Join human approve/deny outcomes to evaluations by evaluation ID; automatic approvals are not labels.
- **D14 — Storage/report:** append owner-only JSONL at `~/.pi/agent/logs/yolo-auto-calibration.jsonl`, mode 0600, rotate at 50 MB with one backup; report joins labels and computes metrics.

## Calibration prerequisite superseded

The original consequence above says a labelled evaluation set is required before auto-allow. The later user-approved implementation plan explicitly accepts the D10 fixed thresholds before historical calibration, with the uncalibrated-model risk recorded in that plan. This supersedes the earlier activation prerequisite; calibration reporting is post-implementation evidence, not an enablement gate. The model remains uncalibrated until labeled results are reviewed.
