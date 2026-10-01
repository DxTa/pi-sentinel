import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, rename, rm, stat, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream as WebReadableStream } from "node:stream/web";
import type { InferenceSession, Tensor } from "onnxruntime-node";
import type { YoloAutoHeads } from "./yolo-auto-policy";
import { parseYoloAutoLabelSchema, YOLO_AUTO_LABEL_SCHEMA } from "./yolo-auto-label-schema.ts";
import { withFileLock } from "./yolo-auto-file-lock.ts";
import { MODEL_REVISION } from "./yolo-auto-build.ts";
export { MODEL_REVISION } from "./yolo-auto-build.ts";

export const MODEL_BASE_URL =
  `https://huggingface.co/patronus-studio/lion-warden-ai-security-classifier/resolve/${MODEL_REVISION}`;

export interface ModelAsset {
  path: string;
  size: number;
  sha256: string;
}

/** Apache-2.0 assets only; GPL `l2/` paths are never fetched. */
export const MODEL_ASSETS: readonly ModelAsset[] = [
  { path: "config.json", size: 3_961, sha256: "1a0d7d997fa51a46177cfe5e8d6652a77f68c0939be92715477bdafb81dbd920" },
  { path: "tokenizer_config.json", size: 574, sha256: "14b147f2a4f939d9b12ab36e9633917040dd948fa78ce283b03402e4cf2c9cba" },
  { path: "tokenizer.json", size: 34_363_188, sha256: "609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f" },
  { path: "onnx/int8_int4_embeddings/model.onnx", size: 96_191_142, sha256: "f94571f4ad719105814583cd4fb7fef5e8127da857bb76ac84d538a337214d44" },
];

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


const MAX_SEQUENCE_LENGTH = 256;
type ModelHead = keyof typeof YOLO_AUTO_LABEL_SCHEMA;

const LOGIT_OUTPUTS: Record<ModelHead, string> = {
  injection: "injection_logits",
  threat: "threat_logits",
  tool_class: "tool_class_logits",
  tool_action: "tool_action_logits",
  tool_tags: "tool_tags_logits",
  sensitive_document: "sensitive_logits",
  routing: "routing_logits",
};

export interface YoloAutoClassifier {
  classify(text: string): Promise<YoloAutoHeads>;
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

function outputLogits(outputs: InferenceSession.ReturnType, name: string, size: number): Float32Array {
  const output = outputs[name] as Tensor | undefined;
  if (!output || output.type !== "float32" || !(output.data instanceof Float32Array) || output.data.length !== size) {
    throw new Error(`Invalid model output: ${name}`);
  }
  return output.data;
}

/** Load verified local model assets and return a CPU classifier. */
export async function createClassifier(modelDir: string): Promise<YoloAutoClassifier> {
  const [{ AutoTokenizer, env }, ort, configText] = await Promise.all([
    import("@huggingface/transformers"),
    import("onnxruntime-node"),
    readFile(join(modelDir, "config.json"), "utf8"),
  ]);
  const config = JSON.parse(configText) as { label_schema?: unknown };
  const labelSchema = parseYoloAutoLabelSchema(config.label_schema);
  env.allowRemoteModels = false;
  const tokenizer = await AutoTokenizer.from_pretrained(modelDir, { local_files_only: true });
  const session = await ort.InferenceSession.create(
    join(modelDir, "onnx/int8_int4_embeddings/model.onnx"),
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
        max_length: MAX_SEQUENCE_LENGTH,
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
      } satisfies YoloAutoHeads;
      return result;
    },
    async close() {
      if (closed) return;
      closed = true;
      await session.release();
    },
  };
}
