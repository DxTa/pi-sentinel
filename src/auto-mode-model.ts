import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, rm, stat, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import type { InferenceSession, Tensor } from "onnxruntime-node";
import type { AutoModeHeads } from "./auto-mode-policy";
import { parseAutoModeLabelSchema } from "./auto-mode-label-schema.ts";
import { withFileLock } from "./auto-mode-file-lock.ts";
import { MODEL_PROFILE } from "./auto-mode-build.ts";
import type { ModelAsset, ModelProfile } from "./auto-mode-profile.ts";
export { MODEL_REVISION } from "./auto-mode-build.ts";
export type { ModelAsset } from "./auto-mode-profile.ts";

export const modelBaseUrl = (profile: ModelProfile) =>
  `https://huggingface.co/${profile.repo}/resolve/${profile.revision}`;
export const MODEL_BASE_URL = modelBaseUrl(MODEL_PROFILE);
/** Apache-2.0 assets only; GPL `l2/` paths are never fetched. */
export const MODEL_ASSETS: readonly ModelAsset[] = MODEL_PROFILE.assets;

/** Model directory: PI_SENTINEL_AUTO_MODEL_DIR, else <agent dir>/runtime/...; shared by the worker and install-time prefetch. */
export function resolveModelDir(env: NodeJS.ProcessEnv = process.env, home: string = homedir()): string {
  const override = env.PI_SENTINEL_AUTO_MODEL_DIR?.trim();
  if (override) return override;
  const agentDir = env.PI_CODING_AGENT_DIR || join(home, ".pi", "agent");
  return join(agentDir, "runtime", "pi-sentinel", "auto-mode", "models");
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface EnsureModelAssetsOptions {
  dir: string;
  fetch?: FetchLike;
  assets?: readonly ModelAsset[];
  baseUrl?: string;
}

async function fileSize(path: string): Promise<number | undefined> {
  try {
    return (await stat(path)).size;
  } catch {
    return undefined;
  }
}

async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function downloadAsset(asset: ModelAsset, dir: string, fetch: FetchLike, baseUrl: string) {
  const target = join(dir, asset.path);
  const part = `${target}.part`;
  if ((await fileSize(target)) === asset.size && await sha256File(target) === asset.sha256) return;
  await rm(target, { force: true });
  await mkdir(dirname(target), { recursive: true });

  for (let attempt = 0; attempt < 2; attempt++) {
    let offset = (await fileSize(part)) ?? 0;
    if (offset >= asset.size) {
      await rm(part, { force: true });
      offset = 0;
    }
    const response = await fetch(`${baseUrl}/${asset.path}`, offset > 0
      ? { headers: { range: `bytes=${offset}-` } }
      : undefined);
    if (!response.ok || !response.body) {
      throw new Error(`Model download failed: ${asset.path} HTTP ${response.status}`);
    }
    const append = offset > 0 && response.status === 206;
    await pipeline(
      Readable.fromWeb(response.body as WebReadableStream<Uint8Array>),
      createWriteStream(part, { flags: append ? "a" : "w" }),
    );
    if ((await fileSize(part)) === asset.size && await sha256File(part) === asset.sha256) {
      await rename(part, target);
      return;
    }
    await rm(part, { force: true });
  }
  throw new Error(`Model asset sha256 mismatch: ${asset.path}`);
}

/** Download missing model assets, resuming partial files and verifying sha256 under a cross-process lock. */
export async function ensureModelAssets(options: EnsureModelAssetsOptions): Promise<void> {
  const { dir, fetch = globalThis.fetch, assets = MODEL_ASSETS, baseUrl = MODEL_BASE_URL } = options;
  await mkdir(dir, { recursive: true });
  await withFileLock(join(dir, ".download.lock"), async () => {
    for (const asset of assets) await downloadAsset(asset, dir, fetch, baseUrl);
  });
}


export interface AutoModeClassifier {
  classify(text: string): Promise<AutoModeHeads>;
  close(): Promise<void>;
}

function probabilities(logits: Float32Array, labels: readonly string[], multiLabel: boolean): Record<string, number> {
  if (logits.some((value) => !Number.isFinite(value))) throw new Error("Model returned non-finite logits.");
  if (multiLabel) {
    if (logits.length !== labels.length) throw new Error("Model output does not match label schema.");
    return Object.fromEntries(labels.map((label, i) => {
      const value = logits[i]!;
      const score = value >= 0 ? 1 / (1 + Math.exp(-value)) : Math.exp(value) / (1 + Math.exp(value));
      return [label, score];
    }));
  }
  if (logits.length !== labels.length) throw new Error("Model output does not match label schema.");
  const max = Math.max(...logits);
  const scores = logits.map((value) => Math.exp(value - max));
  const total = scores.reduce((sum, score) => sum + score, 0);
  return Object.fromEntries(labels.map((label, i) => [label, scores[i]! / total]));
}

function halfToFloat(bits: number): number {
  const exponent = (bits >> 10) & 0x1f;
  const fraction = bits & 0x3ff;
  const sign = bits & 0x8000 ? -1 : 1;
  if (exponent === 0) return sign * 2 ** -14 * (fraction / 1024);
  if (exponent === 0x1f) return fraction ? Number.NaN : sign * Infinity;
  return sign * 2 ** (exponent - 15) * (1 + fraction / 1024);
}

/** Logits as float32; FP16 exports return float16 tensors. */
export function outputLogits(outputs: InferenceSession.ReturnType, name: string, size: number): Float32Array {
  const output = outputs[name] as Tensor | undefined;
  // onnxruntime-node returns float16 data as Float16Array (Node >= 24) or raw Uint16 bits.
  const data = output?.type === "float16"
    ? Float32Array.from(output.data as ArrayLike<number>, output.data instanceof Uint16Array ? halfToFloat : Number)
    : output?.type === "float32" ? output.data : undefined;
  if (!(data instanceof Float32Array) || data.length !== size) {
    throw new Error(`Invalid model output: ${name}`);
  }
  return data;
}

/**
 * Load the tokenizer library and ONNX Runtime (CPU). Both are pi-sentinel
 * dependencies; this fails when the platform has no prebuilt runtime
 * (for example Intel macOS) or the install is incomplete.
 */
export async function loadInferenceRuntime(): Promise<{
  transformers: typeof import("@huggingface/transformers");
  ort: typeof import("onnxruntime-node");
}> {
  try {
    const [transformers, ort] = await Promise.all([
      import("@huggingface/transformers"),
      import("onnxruntime-node"),
    ]);
    return { transformers, ort };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(
      `ONNX Runtime is unavailable on ${process.platform}/${process.arch}: ${reason}. ` +
        "auto mode needs onnxruntime-node and @huggingface/transformers, which install with pi-sentinel; " +
        "reinstall the extension, or use manual or yolo mode on unsupported platforms.",
      { cause: error },
    );
  }
}

/** Load verified local model assets and return a CPU classifier. */
export async function createClassifier(modelDir: string, profile: ModelProfile = MODEL_PROFILE): Promise<AutoModeClassifier> {
  const LOGIT_OUTPUTS = profile.logitOutputs;
  const [{ transformers: { AutoTokenizer, env }, ort }, configText] = await Promise.all([
    loadInferenceRuntime(),
    readFile(join(modelDir, "config.json"), "utf8"),
  ]);
  const config = JSON.parse(configText) as { label_schema?: unknown };
  const labelSchema = parseAutoModeLabelSchema(config.label_schema);
  env.allowRemoteModels = false;
  const tokenizer = await AutoTokenizer.from_pretrained(modelDir, { local_files_only: true });
  const session = await ort.InferenceSession.create(
    join(modelDir, profile.onnxPath),
    { executionProviders: ["cpu"] },
  );
  const requiredOutputs = Object.values(LOGIT_OUTPUTS);
  if (!session.inputNames.includes("input_ids")
    || !session.inputNames.includes("attention_mask")
    || requiredOutputs.some((name) => !session.outputNames.includes(name))) {
    await session.release();
    throw new Error("ONNX model inputs or outputs do not match the classifier.");
  }
  let closed = false;
  return {
    async classify(text) {
      if (closed) throw new Error("Classifier is closed.");
      const encoded = tokenizer(text, {
        truncation: true,
        max_length: profile.maxSequenceLength,
        return_tensor: false,
      });
      const inputIds = BigInt64Array.from(encoded.input_ids, BigInt);
      const attentionMask = BigInt64Array.from(encoded.attention_mask, BigInt);
      const dims = [1, inputIds.length];
      const outputs = await session.run({
        input_ids: new ort.Tensor("int64", inputIds, dims),
        attention_mask: new ort.Tensor("int64", attentionMask, dims),
      });
      const injectionLogit = outputLogits(outputs, LOGIT_OUTPUTS.injection, 1)[0]!;
      const injectionScore = injectionLogit >= 0
        ? 1 / (1 + Math.exp(-injectionLogit))
        : Math.exp(injectionLogit) / (1 + Math.exp(injectionLogit));
      const result = {
        injection: {
          [labelSchema.injection[0]!]: 1 - injectionScore,
          [labelSchema.injection[1]!]: injectionScore,
        },
        threat: probabilities(outputLogits(outputs, LOGIT_OUTPUTS.threat, labelSchema.threat.length), labelSchema.threat, false),
        tool_class: probabilities(outputLogits(outputs, LOGIT_OUTPUTS.tool_class, labelSchema.tool_class.length), labelSchema.tool_class, false),
        tool_action: probabilities(outputLogits(outputs, LOGIT_OUTPUTS.tool_action, labelSchema.tool_action.length), labelSchema.tool_action, false),
        tool_tags: probabilities(outputLogits(outputs, LOGIT_OUTPUTS.tool_tags, labelSchema.tool_tags.length), labelSchema.tool_tags, true),
        sensitive_document: probabilities(outputLogits(outputs, LOGIT_OUTPUTS.sensitive_document, labelSchema.sensitive_document.length), labelSchema.sensitive_document, false),
        routing: probabilities(outputLogits(outputs, LOGIT_OUTPUTS.routing, labelSchema.routing.length), labelSchema.routing, false),
      } satisfies AutoModeHeads;
      return result;
    },
    async close() {
      if (closed) return;
      closed = true;
      await session.release();
    },
  };
}
