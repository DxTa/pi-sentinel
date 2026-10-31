import { randomUUID } from "node:crypto";
import { once } from "node:events";
import * as net from "node:net";

import type { AutoModeHeads } from "./auto-mode-policy.ts";

export const AUTO_MODE_PROTOCOL_VERSION = 2;
export const WORKER_HANDSHAKE_TIMEOUT_MS = 250;
export const CLASSIFICATION_REQUEST_TIMEOUT_MS = 1_000;
export const WORKER_STARTUP_TIMEOUT_MS = 120_000;
export const WORKER_IDLE_EVICTION_MS = 10 * 60 * 1000;
const MAX_FRAME_BYTES = 1024 * 1024;
const READINESS_RETRY_INTERVAL_MS = 50;

export interface AutoModePayload {
  toolName: string;
  operation: string;
  workspaceRelativePath?: string;
  content?: string;
  command?: string;
}

export function buildAutoModeText(payload: AutoModePayload): string {
  if (payload.operation === "exec" && payload.toolName === "bash") {
    return "tool=bash command=" + (payload.command ?? "");
  }
  const path = payload.workspaceRelativePath ? " path=" + payload.workspaceRelativePath : "";
  const content = payload.content === undefined ? "" : " content=" + payload.content.slice(0, 800);
  return "tool=" + payload.toolName + path + content;
}

export interface AutoModeWorkerRequest {
  type: "classify";
  protocolVersion: typeof AUTO_MODE_PROTOCOL_VERSION;
  requestId: string;
  deadlineMs: number;
  text: string;
}

export interface AutoModeWorkerResponse {
  type: "classify";
  protocolVersion: typeof AUTO_MODE_PROTOCOL_VERSION;
  requestId: string;
  status: "complete" | "failed";
  heads?: unknown;
  error?: string;
}

export type AutoModeFailureReason =
  | "worker_unavailable"
  | "build_mismatch"
  | "request_failed"
  | "protocol_mismatch"
  | "worker_failed";

export type AutoModeClientResult =
  | {
      status: "complete";
      evaluationId: string;
      buildId: string;
      totalLatencyMs: number;
      heads: AutoModeHeads;
    }
  | {
      status: "unavailable";
      evaluationId: string;
      totalLatencyMs: number;
      reason: AutoModeFailureReason;
    };

export interface AutoModeWorkerTransport {
  request(request: AutoModeWorkerRequest): Promise<AutoModeWorkerResponse>;
  waitUntilReady(): Promise<string>;
  shutdownWorker(): Promise<void>;
  close(): void;
}

export interface AutoModeClientOptions {
  expectedBuildId: string;
  requestTimeoutMs?: number;
}

export type AutoModeRuntimeStatus =
  | { state: "cold" }
  | { state: "warm" }
  | { state: "fallback"; reason: string };

export class AutoModeBuildMismatchError extends Error {
  readonly actualBuildId: string;
  readonly expectedBuildId: string;

  constructor(actualBuildId: string, expectedBuildId: string) {
    super("AutoMode worker build ID mismatch.");
    this.name = "AutoModeBuildMismatchError";
    this.actualBuildId = actualBuildId;
    this.expectedBuildId = expectedBuildId;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isBuildId(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 256
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function isHeads(value: unknown): value is AutoModeHeads {
  return isRecord(value);
}

function isWorkerResponse(value: unknown): value is AutoModeWorkerResponse {
  return isRecord(value)
    && value.type === "classify"
    && value.protocolVersion === AUTO_MODE_PROTOCOL_VERSION
    && typeof value.requestId === "string"
    && (value.status === "complete" || value.status === "failed");
}

export class AutoModeClient {
  private readonly transport: AutoModeWorkerTransport;
  private readonly expectedBuildId: string;
  private readonly requestTimeoutMs: number;
  private runtimeStatus: AutoModeRuntimeStatus = { state: "cold" };

  constructor(transport: AutoModeWorkerTransport, options: AutoModeClientOptions) {
    this.transport = transport;
    this.expectedBuildId = options.expectedBuildId;
    this.requestTimeoutMs = options.requestTimeoutMs ?? CLASSIFICATION_REQUEST_TIMEOUT_MS;
  }

  async evaluate(text: string): Promise<AutoModeClientResult> {
    const evaluationId = randomUUID();
    const startedAt = Date.now();
    let buildId: string;
    try {
      buildId = await this.waitUntilReady();
    } catch (error) {
      const reason = error instanceof AutoModeBuildMismatchError
        ? "build_mismatch"
        : "worker_unavailable";
      this.runtimeStatus = { state: "fallback", reason };
      return this.unavailable(evaluationId, startedAt, reason);
    }

    const request: AutoModeWorkerRequest = {
      type: "classify",
      protocolVersion: AUTO_MODE_PROTOCOL_VERSION,
      requestId: evaluationId,
      deadlineMs: this.requestTimeoutMs,
      text,
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("request_timeout")), request.deadlineMs);
      });
      const response = await Promise.race([this.transport.request(request), timeout]);
      if (!isWorkerResponse(response) || response.requestId !== request.requestId) {
        this.runtimeStatus = { state: "fallback", reason: "protocol_mismatch" };
        return this.unavailable(evaluationId, startedAt, "protocol_mismatch");
      }
      if (response.status === "failed") {
        this.runtimeStatus = { state: "fallback", reason: "worker_failed" };
        return this.unavailable(evaluationId, startedAt, "worker_failed");
      }
      if (!isHeads(response.heads)) {
        this.runtimeStatus = { state: "fallback", reason: "protocol_mismatch" };
        return this.unavailable(evaluationId, startedAt, "protocol_mismatch");
      }
      this.runtimeStatus = { state: "warm" };
      return {
        status: "complete",
        evaluationId,
        buildId,
        totalLatencyMs: Math.max(0, Date.now() - startedAt),
        heads: response.heads,
      };
    } catch {
      this.runtimeStatus = { state: "fallback", reason: "request_failed" };
      return this.unavailable(evaluationId, startedAt, "request_failed");
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async waitUntilReady(): Promise<string> {
    const actualBuildId = await this.transport.waitUntilReady();
    if (!isBuildId(actualBuildId)) throw new Error("Worker handshake has an invalid build ID.");
    if (actualBuildId !== this.expectedBuildId) {
      await this.transport.shutdownWorker();
      throw new AutoModeBuildMismatchError(actualBuildId, this.expectedBuildId);
    }
    return actualBuildId;
  }

  close(): void {
    this.transport.close();
  }

  getStatus(): AutoModeRuntimeStatus {
    return this.runtimeStatus;
  }

  private unavailable(
    evaluationId: string,
    startedAt: number,
    reason: AutoModeFailureReason,
  ): AutoModeClientResult {
    return {
      status: "unavailable",
      evaluationId,
      totalLatencyMs: Math.max(0, Date.now() - startedAt),
      reason,
    };
  }
}

export function createUnixSocketWorkerTransport(
  socketPath: string,
): AutoModeWorkerTransport {
  let socket: net.Socket | undefined;
  let connecting: Promise<net.Socket> | undefined;
  let connectingSocket: net.Socket | undefined;
  let closed = false;
  let buildId: string | undefined;
  let buffer = Buffer.alloc(0);
  const pending = new Map<string, {
    resolve: (response: AutoModeWorkerResponse) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();
  let handshakeResolve: ((value: string) => void) | undefined;
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
    if (!isRecord(parsed)) {
      socket?.destroy(new Error("Invalid worker response frame."));
      return;
    }
    if (parsed.type === "handshake") {
      if (
        parsed.protocolVersion !== AUTO_MODE_PROTOCOL_VERSION
        || parsed.status !== "ready"
        || !isBuildId(parsed.buildId)
      ) {
        handshakeReject?.(new Error("Worker handshake failed."));
        socket?.destroy(new Error("Worker handshake failed."));
        return;
      }
      buildId = parsed.buildId;
      handshakeResolve?.(parsed.buildId);
      handshakeResolve = undefined;
      handshakeReject = undefined;
      return;
    }
    if (typeof parsed.requestId !== "string") {
      socket?.destroy(new Error("Worker response missing request ID."));
      return;
    }
    const entry = pending.get(parsed.requestId);
    if (!entry) {
      socket?.destroy(new Error("Worker response has unknown request ID."));
      return;
    }
    pending.delete(parsed.requestId);
    clearTimeout(entry.timer);
    entry.resolve(parsed as unknown as AutoModeWorkerResponse);
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
    if (connecting) return connecting;
    if (closed) return Promise.reject(new Error("Worker transport closed."));
    if (socket && !socket.destroyed && buildId) return Promise.resolve(socket);

    const candidate = net.createConnection(socketPath);
    connectingSocket = candidate;
    const controller = new AbortController();
    connecting = Promise.race([
      once(candidate, "connect", { signal: controller.signal }),
      once(candidate, "close", { signal: controller.signal }).then(() => {
        throw new Error("Worker socket closed.");
      }),
    ]).then(async () => {
      controller.abort();
      if (candidate.destroyed) throw new Error("Worker transport closed.");
      socket = candidate;
      candidate.on("data", handleData);
      const handleDisconnect = (error: Error): void => {
        if (socket === candidate) {
          socket = undefined;
          buildId = undefined;
        }
        handshakeReject?.(error);
        rejectPending(error);
      };
      candidate.on("error", handleDisconnect);
      candidate.on("close", () => handleDisconnect(new Error("Worker socket closed.")));
      const handshakeTimer = setTimeout(() => {
        handshakeReject?.(new Error("Worker handshake timed out."));
        candidate.destroy();
      }, WORKER_HANDSHAKE_TIMEOUT_MS);
      const handshake = new Promise<string>((handshakeDone, handshakeFailed) => {
        handshakeResolve = (id) => {
          clearTimeout(handshakeTimer);
          handshakeResolve = undefined;
          handshakeReject = undefined;
          handshakeDone(id);
        };
        handshakeReject = (error) => {
          clearTimeout(handshakeTimer);
          handshakeResolve = undefined;
          handshakeReject = undefined;
          handshakeFailed(error);
        };
      });
      await Promise.all([
        writeFrame(candidate, { type: "handshake", protocolVersion: AUTO_MODE_PROTOCOL_VERSION }),
        handshake,
      ]);
      if (closed || candidate.destroyed) throw new Error("Worker transport closed.");
      return candidate;
    }).catch((error: unknown) => {
      if (socket === candidate) {
        socket = undefined;
        buildId = undefined;
      }
      candidate.destroy();
      throw error instanceof Error ? error : new Error(String(error));
    }).finally(() => {
      controller.abort();
      connectingSocket = undefined;
      connecting = undefined;
    });
    return connecting;
  };

  return {
    async waitUntilReady() {
      const deadline = Date.now() + WORKER_STARTUP_TIMEOUT_MS;
      while (true) {
        try {
          await connect();
          if (!buildId) throw new Error("Worker handshake did not provide a build ID.");
          return buildId;
        } catch (error) {
          const code = error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined;
          const remaining = deadline - Date.now();
          if ((code !== "ECONNREFUSED" && code !== "ENOENT") || remaining <= 0) throw error;
          await new Promise<void>((resolve) =>
            setTimeout(resolve, Math.min(READINESS_RETRY_INTERVAL_MS, remaining)));
        }
      }
    },
    async request(request) {
      const activeSocket = await connect();
      return new Promise<AutoModeWorkerResponse>((resolve, reject) => {
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
    async shutdownWorker() {
      const activeSocket = await connect();
      const socketClosed = once(activeSocket, "close").then(() => undefined, () => undefined);
      await writeFrame(activeSocket, {
        type: "shutdown",
        protocolVersion: AUTO_MODE_PROTOCOL_VERSION,
      });
      await socketClosed;
    },
    close() {
      closed = true;
      const error = new Error("Worker transport closed.");
      const pendingSocket = connectingSocket;
      const activeSocket = socket;
      socket = undefined;
      connectingSocket = undefined;
      connecting = undefined;
      buildId = undefined;
      pendingSocket?.destroy(error);
      activeSocket?.destroy(error);
      rejectPending(error);
    },
  };
}
