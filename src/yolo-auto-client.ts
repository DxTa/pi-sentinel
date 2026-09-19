import { randomUUID } from "node:crypto";
import * as net from "node:net";

import {
  type YoloAutoClassifierResult,
  type YoloAutoL1Response,
} from "./yolo-auto-policy";

export const L1_REQUEST_TIMEOUT_MS = 250;
export const L2_REQUEST_TIMEOUT_MS = 250;
export const L3_ESCALATION_TIMEOUT_MS = 1000;
export const WORKER_IDLE_EVICTION_MS = 10 * 60 * 1000;

export interface YoloAutoPayload {
  toolName: string;
  operation: string;
  workspaceRelativePath?: string;
  metadata?: Record<string, string | number | boolean>;
}

export const YOLO_AUTO_PROTOCOL_VERSION = 1;

export interface YoloAutoWorkerRequest {
  protocolVersion: typeof YOLO_AUTO_PROTOCOL_VERSION;
  requestId: string;
  phase: "l1" | "l2" | "l3";
  deadlineMs: number;
  payload: YoloAutoPayload;
}

export interface YoloAutoL2Response {
  results: readonly YoloAutoClassifierResult[];
  escalated: boolean;
}

export interface YoloAutoL3Response {
  recommendation: "allow" | "prompt" | "block" | "review";
  provenance?: string;
}

export interface YoloAutoWorkerResponse {
  requestId: string;
  phase: "l1" | "l2" | "l3";
  completion: "complete" | "failed";
  l1?: YoloAutoL1Response;
  l2?: YoloAutoL2Response;
  l3?: YoloAutoL3Response;
  error?: string;
}

export interface YoloAutoWorkerHandshakeResponse {
  type: "handshake";
  protocolVersion: typeof YOLO_AUTO_PROTOCOL_VERSION;
  status: "ready" | "failed";
  capabilities?: {
    l1Ready: boolean;
    l2Ready: boolean;
    l3Available: boolean;
    l3Strategy?: "multi";
  };
  error?: string;
}

export interface YoloAutoWorkerTransport {
  request(request: YoloAutoWorkerRequest): Promise<YoloAutoWorkerResponse>;
  close?(): void;
}

export type YoloAutoClientResult =
  | {
      status: "complete";
      l1: YoloAutoL1Response;
      l2: YoloAutoL2Response | undefined;
      l3: YoloAutoL3Response | undefined;
      escalated: boolean;
    }
  | {
      status: "unavailable";
      reason: string;
      escalated: boolean;
    };

export interface YoloAutoClientOptions {
  l1RequestTimeoutMs?: number;
  l2RequestTimeoutMs?: number;
  l3EscalationTimeoutMs?: number;
}

export type YoloAutoRuntimeStatus =
  | { state: "cold" }
  | { state: "warm" }
  | { state: "fallback"; reason: string };

function isClassifierResult(value: unknown): value is YoloAutoClassifierResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Record<string, unknown>;
  return typeof result.category === "string"
    && typeof result.className === "string"
    && (result.pipeline === undefined || typeof result.pipeline === "string")
    && typeof result.accepted === "boolean"
    && typeof result.complete === "boolean"
    && typeof result.degraded === "boolean";
}

function isL1Response(value: unknown): value is YoloAutoL1Response {
  if (!value || typeof value !== "object") return false;
  const response = value as Record<string, unknown>;
  return (response.verdict === "safe"
    || response.verdict === "unsafe"
    || response.verdict === "unknown")
    && typeof response.accepted === "boolean"
    && typeof response.complete === "boolean"
    && typeof response.degraded === "boolean"
    && (response.provenance === undefined || typeof response.provenance === "string");
}

function isL2Response(value: unknown): value is YoloAutoL2Response {
  if (!value || typeof value !== "object") return false;
  const response = value as Record<string, unknown>;
  return typeof response.escalated === "boolean"
    && Array.isArray(response.results)
    && response.results.every(isClassifierResult);
}

function isL3Response(value: unknown): value is YoloAutoL3Response {
  if (!value || typeof value !== "object") return false;
  const response = value as Record<string, unknown>;
  return response.recommendation === "allow"
    || response.recommendation === "prompt"
    || response.recommendation === "block"
    || response.recommendation === "review";
}

function isSafeL1(response: YoloAutoL1Response): boolean {
  return response.verdict === "safe"
    && response.accepted
    && response.complete
    && !response.degraded;
}

export class YoloAutoClient {
  private runtimeStatus: YoloAutoRuntimeStatus = { state: "cold" };
  private readonly l1RequestTimeoutMs: number;
  private readonly l2RequestTimeoutMs: number;
  private readonly l3EscalationTimeoutMs: number;

  constructor(
    private readonly transport: YoloAutoWorkerTransport,
    options: YoloAutoClientOptions = {},
  ) {
    this.l1RequestTimeoutMs = options.l1RequestTimeoutMs ?? L1_REQUEST_TIMEOUT_MS;
    this.l2RequestTimeoutMs = options.l2RequestTimeoutMs ?? L2_REQUEST_TIMEOUT_MS;
    this.l3EscalationTimeoutMs = options.l3EscalationTimeoutMs ?? L3_ESCALATION_TIMEOUT_MS;
  }

  async evaluate(
    payload: YoloAutoPayload,
    maxLevel: "l1" | "l2" | "l3" = "l3",
  ): Promise<YoloAutoClientResult> {
    const requestId = randomUUID();
    const l1Response = await this.request({
      protocolVersion: YOLO_AUTO_PROTOCOL_VERSION,
      requestId,
      phase: "l1",
      deadlineMs: this.l1RequestTimeoutMs,
      payload,
    });
    if (l1Response.status === "unavailable") {
      this.runtimeStatus = { state: "fallback", reason: l1Response.reason };
      return l1Response;
    }

    const l1 = l1Response.response.l1;
    if (!isL1Response(l1)) {
      this.runtimeStatus = { state: "fallback", reason: "protocol_mismatch" };
      return { status: "unavailable", reason: "protocol_mismatch", escalated: false };
    }
    if (!isSafeL1(l1) || maxLevel === "l1") {
      this.runtimeStatus = { state: "warm" };
      return { status: "complete", l1, l2: undefined, l3: undefined, escalated: false };
    }

    const l2Response = await this.request({
      protocolVersion: YOLO_AUTO_PROTOCOL_VERSION,
      requestId,
      phase: "l2",
      deadlineMs: this.l2RequestTimeoutMs,
      payload,
    });
    if (l2Response.status === "unavailable") {
      this.runtimeStatus = { state: "fallback", reason: l2Response.reason };
      return l2Response;
    }

    const l2 = l2Response.response.l2;
    if (!isL2Response(l2)) {
      this.runtimeStatus = { state: "fallback", reason: "protocol_mismatch" };
      return { status: "unavailable", reason: "protocol_mismatch", escalated: false };
    }
    if (!l2.escalated || maxLevel === "l2") {
      this.runtimeStatus = { state: "warm" };
      return { status: "complete", l1, l2, l3: undefined, escalated: l2.escalated };
    }

    const l3Response = await this.request({
      protocolVersion: YOLO_AUTO_PROTOCOL_VERSION,
      requestId,
      phase: "l3",
      deadlineMs: this.l3EscalationTimeoutMs,
      payload,
    });
    if (l3Response.status === "unavailable") {
      this.runtimeStatus = { state: "fallback", reason: l3Response.reason };
      return { ...l3Response, escalated: true };
    }
    if (!isL3Response(l3Response.response.l3)) {
      this.runtimeStatus = { state: "fallback", reason: "protocol_mismatch" };
      return { status: "unavailable", reason: "protocol_mismatch", escalated: true };
    }

    this.runtimeStatus = { state: "warm" };
    return {
      status: "complete",
      l1,
      l2,
      l3: l3Response.response.l3,
      escalated: true,
    };
  }

  close(): void {
    this.transport.close?.();
  }

  getStatus(): YoloAutoRuntimeStatus {
    return this.runtimeStatus;
  }

  private async request(request: YoloAutoWorkerRequest): Promise<
    | { status: "complete"; response: YoloAutoWorkerResponse }
    | { status: "unavailable"; reason: string; escalated: boolean }
  > {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("request_timeout")), request.deadlineMs);
      });
      const response = await Promise.race([this.transport.request(request), timeout]);
      if (
        response.requestId !== request.requestId
        || response.phase !== request.phase
        || response.completion !== "complete"
      ) {
        return { status: "unavailable", reason: "protocol_mismatch", escalated: false };
      }
      return { status: "complete", response };
    } catch {
      return {
        status: "unavailable",
        reason: request.phase === "l1"
          ? "l1_request_failed"
          : request.phase === "l2"
            ? "l2_request_failed"
            : "l3_request_failed",
        escalated: request.phase === "l3",
      };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}

const MAX_FRAME_BYTES = 1024 * 1024;

export function createUnixSocketWorkerTransport(
  socketPath: string,
): YoloAutoWorkerTransport {
  let socket: net.Socket | undefined;
  let connecting: Promise<net.Socket> | undefined;
  let buffer = Buffer.alloc(0);
  const pending = new Map<string, {
    resolve: (response: YoloAutoWorkerResponse) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();
  let handshakeResolve: (() => void) | undefined;
  let handshakeReject: ((error: Error) => void) | undefined;

  const rejectPending = (error: Error) => {
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
    pending.clear();
  };

  const handleFrame = (frame: Buffer) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(frame.toString("utf8"));
    } catch {
      socket?.destroy(new Error("Invalid worker response JSON."));
      return;
    }
    if (!parsed || typeof parsed !== "object") {
      socket?.destroy(new Error("Invalid worker response frame."));
      return;
    }
    if ((parsed as { type?: unknown }).type === "handshake") {
      const handshake = parsed as Partial<YoloAutoWorkerHandshakeResponse>;
      if (
        handshake.protocolVersion !== YOLO_AUTO_PROTOCOL_VERSION
        || handshake.status !== "ready"
        || handshake.capabilities?.l1Ready !== true
        || handshake.capabilities?.l2Ready !== true
      ) {
        handshakeReject?.(new Error(handshake.error ?? "Worker handshake failed."));
        socket?.destroy(new Error("Worker handshake failed."));
        return;
      }
      handshakeResolve?.();
      handshakeResolve = undefined;
      handshakeReject = undefined;
      return;
    }
    const response = parsed as Partial<YoloAutoWorkerResponse>;
    if (typeof response.requestId !== "string") {
      socket?.destroy(new Error("Worker response missing request ID."));
      return;
    }
    const entry = pending.get(response.requestId);
    if (!entry) {
      socket?.destroy(new Error("Worker response has unknown request ID."));
      return;
    }
    pending.delete(response.requestId);
    clearTimeout(entry.timer);
    entry.resolve(response as YoloAutoWorkerResponse);
  };

  const handleData = (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4) {
      const frameLength = buffer.readUInt32BE(0);
      if (frameLength > MAX_FRAME_BYTES) {
        socket?.destroy(new Error("Worker response frame is too large."));
        return;
      }
      if (buffer.length < frameLength + 4) return;
      handleFrame(buffer.subarray(4, frameLength + 4));
      buffer = buffer.subarray(frameLength + 4);
    }
  };

  const writeFrame = (candidate: net.Socket, value: unknown): Promise<void> => {
    const frame = Buffer.from(JSON.stringify(value), "utf8");
    if (frame.length > MAX_FRAME_BYTES) {
      return Promise.reject(new Error("Worker request frame is too large."));
    }
    const header = Buffer.alloc(4);
    header.writeUInt32BE(frame.length, 0);
    return new Promise<void>((resolve, reject) => {
      candidate.write(Buffer.concat([header, frame]), (error) =>
        error ? reject(error) : resolve());
    });
  };

  const connect = (): Promise<net.Socket> => {
    if (socket && !socket.destroyed) return Promise.resolve(socket);
    if (connecting) return connecting;

    connecting = new Promise<net.Socket>((resolve, reject) => {
      const candidate = net.createConnection(socketPath);
      const fail = (error: Error) => {
        candidate.removeAllListeners();
        candidate.destroy();
        socket = undefined;
        connecting = undefined;
        reject(error);
      };
      candidate.once("connect", () => {
        candidate.removeListener("error", fail);
        socket = candidate;
        candidate.on("data", handleData);
        candidate.on("error", (error) => {
          socket = undefined;
          handshakeReject?.(error);
          rejectPending(error);
        });
        candidate.on("close", () => {
          socket = undefined;
          handshakeReject?.(new Error("Worker socket closed."));
          rejectPending(new Error("Worker socket closed."));
        });
        const handshakeTimer = setTimeout(() => {
          handshakeReject?.(new Error("Worker handshake timed out."));
          candidate.destroy();
        }, L1_REQUEST_TIMEOUT_MS);
        const handshake = new Promise<void>((handshakeDone, handshakeFailed) => {
          handshakeResolve = () => {
            clearTimeout(handshakeTimer);
            handshakeDone();
          };
          handshakeReject = (error) => {
            clearTimeout(handshakeTimer);
            handshakeFailed(error);
          };
        });
        void writeFrame(candidate, {
          type: "handshake",
          protocolVersion: YOLO_AUTO_PROTOCOL_VERSION,
          client: "pi-sentinel",
          capabilities: { l1: true, l2: true, l3Escalation: true },
        }).then(() => handshake).then(
          () => {
            connecting = undefined;
            resolve(candidate);
          },
          (error: unknown) => {
            connecting = undefined;
            if (socket === candidate) socket = undefined;
            candidate.destroy();
            reject(error instanceof Error ? error : new Error(String(error)));
          },
        );
      });
      candidate.once("error", fail);
    });
    return connecting;
  };

  return {
    async request(request) {
      const activeSocket = await connect();
      return new Promise<YoloAutoWorkerResponse>((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(request.requestId);
          activeSocket.destroy(new Error("Worker request timed out."));
          reject(new Error("Worker request timed out."));
        }, request.deadlineMs);
        pending.set(request.requestId, { resolve, reject, timer });
        void writeFrame(activeSocket, request).catch((error: unknown) => {
          pending.delete(request.requestId);
          clearTimeout(timer);
          reject(error instanceof Error ? error : new Error(String(error)));
        });
      });
    },
    close() {
      socket?.destroy();
      socket = undefined;
      connecting = undefined;
      rejectPending(new Error("Worker transport closed."));
    },
  };
}
