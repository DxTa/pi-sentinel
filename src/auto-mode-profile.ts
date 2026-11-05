import { readFileSync } from "node:fs";

import { AUTO_MODE_LABEL_SCHEMA, type AutoModeHeadName } from "./auto-mode-label-schema.ts";

export const MODEL_INPUT_FORMATS = ["kv", "json"] as const;
export type ModelInputFormat = (typeof MODEL_INPUT_FORMATS)[number];

/** `tool` is an MCP tool call; code does not know its effect, so the model's tool_action decides. */
export const AUTO_MODE_OPERATIONS = ["read", "list", "write", "edit", "exec", "tool"] as const;
export type AutoModeOperation = (typeof AUTO_MODE_OPERATIONS)[number];

export interface AutoModeThresholds {
  minBenignThreat: number;
  maxInjection: number;
  maxToolTag: number;
}

/** `default` applies to every operation without its own entry. */
export type AutoModeThresholdSet = { default: AutoModeThresholds } & Partial<Record<AutoModeOperation, AutoModeThresholds>>;

export interface ModelAsset {
  path: string;
  size: number;
  sha256: string;
}

/** Everything that changes when the classifier model is swapped. */
export interface ModelProfile {
  id: string;
  repo: string;
  revision: string;
  onnxPath: string;
  maxSequenceLength: number;
  /** How a tool call is written as model input: `kv` = `tool=bash command=...`, `json` = `{"arguments":...,"tool_name":...}`. */
  inputFormat: ModelInputFormat;
  assets: readonly ModelAsset[];
  logitOutputs: Record<AutoModeHeadName, string>;
  thresholds: AutoModeThresholdSet;
}

const THRESHOLD_KEYS = ["minBenignThreat", "maxInjection", "maxToolTag"] as const;
const isProbability = (value: unknown) => typeof value === "number" && value >= 0 && value <= 1;

const SAFE_RELATIVE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\w.\-/]+$/;
const isString = (value: unknown): value is string => typeof value === "string" && value.length > 0;

/** Validate a parsed profile; profile paths are joined onto the model dir, so they must stay inside it. */
export function parseModelProfile(value: unknown): ModelProfile {
  const fail = (field: string): never => { throw new Error("Invalid model profile: " + field); };
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("not an object");
  const p = value as Record<string, unknown>;
  if (!isString(p.id) || !/^[\w.-]+$/.test(p.id)) fail("id");
  if (!isString(p.repo) || !/^[\w.-]+\/[\w.-]+$/.test(p.repo)) fail("repo");
  if (!isString(p.revision) || !/^[0-9a-f]{40}$/.test(p.revision)) fail("revision");
  if (!isString(p.onnxPath) || !SAFE_RELATIVE_PATH.test(p.onnxPath)) fail("onnxPath");
  if (!Number.isInteger(p.maxSequenceLength) || (p.maxSequenceLength as number) <= 0) fail("maxSequenceLength");
  if (!MODEL_INPUT_FORMATS.includes(p.inputFormat as ModelInputFormat)) fail("inputFormat");
  if (!Array.isArray(p.assets) || p.assets.length === 0) fail("assets");
  for (const asset of p.assets as unknown[]) {
    const a = (asset ?? {}) as Record<string, unknown>;
    if (!isString(a.path) || !SAFE_RELATIVE_PATH.test(a.path)
      || !Number.isInteger(a.size) || (a.size as number) <= 0
      || !isString(a.sha256) || !/^[0-9a-f]{64}$/.test(a.sha256)) fail("assets");
  }
  if (!(p.assets as ModelAsset[]).some((a) => a.path === p.onnxPath)) fail("onnxPath not in assets");
  const outputs = (p.logitOutputs ?? {}) as Record<string, unknown>;
  for (const head of Object.keys(AUTO_MODE_LABEL_SCHEMA)) {
    if (!isString(outputs[head])) fail("logitOutputs." + head);
  }
  const thresholds = p.thresholds as Record<string, Record<string, unknown>> | undefined;
  if (!thresholds || typeof thresholds !== "object" || !thresholds.default) fail("thresholds.default");
  for (const [key, set] of Object.entries(thresholds!)) {
    if (key !== "default" && !AUTO_MODE_OPERATIONS.includes(key as AutoModeOperation)) fail("thresholds." + key);
    if (!set || typeof set !== "object" || THRESHOLD_KEYS.some((k) => !isProbability(set[k]))) fail("thresholds." + key);
  }
  return p as unknown as ModelProfile;
}

export function loadModelProfile(id: string): ModelProfile {
  if (!/^[\w.-]+$/.test(id)) throw new Error("Invalid model profile id.");
  const url = new URL(`../profiles/models/${id}.json`, import.meta.url);
  return parseModelProfile(JSON.parse(readFileSync(url, "utf8")));
}

// fp16 allows more safe calls than int8 at the same zero-leak bar (scripts/calibration-baseline-fp16.txt); ~200 ms p95 on CPU.
export const DEFAULT_MODEL_PROFILE_ID = "lion-warden-fp16";
