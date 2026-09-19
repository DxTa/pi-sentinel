import { chmod, mkdir, rm, stat } from "node:fs/promises";
import { dirname } from "node:path";
import * as net from "node:net";

import {
  type YoloAutoL2Response,
  type YoloAutoL3Response,
  type YoloAutoPayload,
  type YoloAutoWorkerRequest,
  type YoloAutoWorkerResponse,
  YOLO_AUTO_PROTOCOL_VERSION,
  L1_REQUEST_TIMEOUT_MS,
  WORKER_IDLE_EVICTION_MS,
} from "./yolo-auto-client";
import type { YoloAutoL1Response } from "./yolo-auto-policy";

const MAX_FRAME_BYTES = 1024 * 1024;
const DEFAULT_QUEUE_LIMIT = 32;

export type WorkerProvider = {
  warmL1(): Promise<void>;
  evaluateL1(payload: YoloAutoPayload): Promise<YoloAutoL1Response>;
  warmL2(): Promise<void>;
  evaluateL2(payload: YoloAutoPayload): Promise<YoloAutoL2Response>;
  warmL3?(): Promise<void>;
  evaluateL3(payload: YoloAutoPayload): Promise<YoloAutoL3Response>;
  close?(): Promise<void> | void;
};

export interface YoloAutoWorkerServerOptions {
  socketPath: string;
  provider: WorkerProvider;
  queueLimit?: number;
  idleEvictionMs?: number;
}

interface QueuedRequest {
  socket: net.Socket;
  request: YoloAutoWorkerRequest;
}

function isWorkerPayload(value: unknown): value is YoloAutoPayload {
  if (!value || typeof value !== "object") return false;
  const payload = value as Record<string, unknown>;
  return typeof payload.toolName === "string"
    && payload.toolName.length > 0
    && payload.toolName.length <= 256
    && typeof payload.operation === "string"
    && payload.operation.length > 0
    && payload.operation.length <= 32
    && (payload.workspaceRelativePath === undefined
      || (typeof payload.workspaceRelativePath === "string"
        && payload.workspaceRelativePath.length <= 4096
        && !payload.workspaceRelativePath.startsWith("/")))
    && (payload.metadata === undefined || (
      typeof payload.metadata === "object"
      && payload.metadata !== null
      && Object.values(payload.metadata as Record<string, unknown>).every(
        (entry) => ["string", "number", "boolean"].includes(typeof entry),
      )
    ));
}

function encodeFrame(value: unknown): Buffer {
  const frame = Buffer.from(JSON.stringify(value), "utf8");
  if (frame.length > MAX_FRAME_BYTES) {
    throw new Error("Worker frame is too large.");
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(frame.length, 0);
  return Buffer.concat([header, frame]);
}

async function removeStaleSocket(socketPath: string): Promise<void> {
  try {
    const socketStat = await stat(socketPath);
    if (!socketStat.isSocket()) {
      throw new Error(`Worker socket path is not a Unix socket: ${socketPath}`);
    }
    await new Promise<void>((resolve, reject) => {
      const probe = net.createConnection(socketPath);
      const timer = setTimeout(() => {
        probe.destroy();
        reject(new Error(`Worker socket is already active: ${socketPath}`));
      }, 250);
      probe.once("connect", () => {
        clearTimeout(timer);
        probe.destroy();
        reject(new Error(`Worker socket is already active: ${socketPath}`));
      });
      probe.once("error", (error: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        probe.destroy();
        if (error.code === "ECONNREFUSED" || error.code === "ENOENT") resolve();
        else reject(error);
      });
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes("already active")) throw error;
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await rm(socketPath, { force: true });
}

export class YoloAutoWorkerServer {
  private readonly server = net.createServer((socket) => this.accept(socket));
  private readonly queue: QueuedRequest[] = [];
  private readonly sockets = new Set<net.Socket>();
  private readonly queueLimit: number;
  private readonly idleEvictionMs: number;
  private busy = false;
  private l3Ready = false;
  private l3Warmup: Promise<void> | undefined;
  private lastActivity = Date.now();
  private idleTimer: ReturnType<typeof setInterval> | undefined;
  private closePromise: Promise<void> | undefined;

  constructor(private readonly options: YoloAutoWorkerServerOptions) {
    this.queueLimit = options.queueLimit ?? DEFAULT_QUEUE_LIMIT;
    this.idleEvictionMs = options.idleEvictionMs ?? WORKER_IDLE_EVICTION_MS;
  }

  async start(): Promise<void> {
    await mkdir(dirname(this.options.socketPath), { recursive: true, mode: 0o700 });
    await chmod(dirname(this.options.socketPath), 0o700);
    await removeStaleSocket(this.options.socketPath);
    await this.options.provider.warmL1();
    await this.options.provider.warmL2();
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        this.server.removeListener("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        this.server.removeListener("error", onError);
        resolve();
      };
      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen(this.options.socketPath);
    });
    await chmod(this.options.socketPath, 0o600);
    this.idleTimer = setInterval(() => this.evictIfIdle(), 1000);
  }

  close(): Promise<void> {
    this.closePromise ??= this.closeInternal();
    return this.closePromise;
  }

  private async closeInternal(): Promise<void> {
    if (this.idleTimer) clearInterval(this.idleTimer);
    this.idleTimer = undefined;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    await new Promise<void>((resolve) => {
      if (!this.server.listening) {
        resolve();
        return;
      }
      this.server.close(() => resolve());
    });
    await rm(this.options.socketPath, { force: true });
    await this.options.provider.close?.();
  }

  private send(socket: net.Socket, value: unknown): void {
    try {
      socket.write(encodeFrame(value));
    } catch {
      socket.destroy();
    }
  }

  private accept(socket: net.Socket): void {
    this.sockets.add(socket);
    let buffer = Buffer.alloc(0);
    let handshaken = false;
    const handshakeTimer = setTimeout(() => socket.destroy(), L1_REQUEST_TIMEOUT_MS);
    const send = (value: unknown): void => {
      try {
        socket.write(encodeFrame(value));
      } catch {
        socket.destroy();
      }
    };
    const failHandshake = (error: string): void => {
      send({
        type: "handshake",
        protocolVersion: YOLO_AUTO_PROTOCOL_VERSION,
        status: "failed",
        error,
      });
      socket.destroy();
    };
    const handleFrame = (frame: Buffer): void => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(frame.toString("utf8"));
      } catch {
        socket.destroy();
        return;
      }
      if (!parsed || typeof parsed !== "object") {
        socket.destroy();
        return;
      }
      if (!handshaken) {
        const handshake = parsed as Record<string, unknown>;
        if (
          handshake.type !== "handshake"
          || handshake.protocolVersion !== YOLO_AUTO_PROTOCOL_VERSION
        ) {
          failHandshake("unsupported_protocol");
          return;
        }
        handshaken = true;
        clearTimeout(handshakeTimer);
        send({
          type: "handshake",
          protocolVersion: YOLO_AUTO_PROTOCOL_VERSION,
          status: "ready",
          capabilities: {
            l1Ready: true,
            l2Ready: true,
            l3Available: typeof this.options.provider.evaluateL3 === "function",
            l3Strategy: "multi",
          },
        });
        return;
      }
      const request = parsed as Partial<YoloAutoWorkerRequest>;
      if (
        request.protocolVersion !== YOLO_AUTO_PROTOCOL_VERSION
        || typeof request.requestId !== "string"
        || (request.phase !== "l1" && request.phase !== "l2" && request.phase !== "l3")
        || typeof request.deadlineMs !== "number"
        || !Number.isFinite(request.deadlineMs)
        || request.deadlineMs <= 0
        || request.deadlineMs > 10_000
        || !isWorkerPayload(request.payload)
      ) {
        socket.destroy();
        return;
      }
      this.lastActivity = Date.now();
      if (this.queue.length >= this.queueLimit) {
        send(this.failedResponse(request, "queue_overflow"));
        return;
      }
      this.queue.push({ socket, request: request as YoloAutoWorkerRequest });
      void this.drain();
    };
    const handleData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (length > MAX_FRAME_BYTES) {
          socket.destroy();
          return;
        }
        if (buffer.length < length + 4) return;
        handleFrame(buffer.subarray(4, length + 4));
        buffer = buffer.subarray(length + 4);
      }
    };
    socket.on("data", handleData);
    socket.on("close", () => {
      clearTimeout(handshakeTimer);
      this.sockets.delete(socket);
      for (let index = this.queue.length - 1; index >= 0; index--) {
        if (this.queue[index]?.socket === socket) this.queue.splice(index, 1);
      }
    });
    socket.on("error", () => undefined);
  }

  private async drain(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      while (this.queue.length > 0) {
        const entry = this.queue.shift();
        if (!entry || entry.socket.destroyed) continue;
        this.lastActivity = Date.now();
        try {
          const result = await this.evaluate(entry.request);
          if (!entry.socket.destroyed) {
            this.send(entry.socket, {
              requestId: entry.request.requestId,
              phase: entry.request.phase,
              completion: "complete",
              ...(entry.request.phase === "l1"
                ? { l1: result }
                : entry.request.phase === "l2"
                  ? { l2: result }
                  : { l3: result }),
            });
          }
        } catch (error) {
          if (!entry.socket.destroyed) {
            this.send(entry.socket, this.failedResponse(entry.request, error instanceof Error ? error.message : String(error)));
          }
        }
      }
    } finally {
      this.busy = false;
    }
  }


  private async evaluate(
    request: YoloAutoWorkerRequest,
  ): Promise<YoloAutoL1Response | YoloAutoL2Response | YoloAutoL3Response> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("deadline_exceeded")), request.deadlineMs);
    });
    const evaluation = request.phase === "l1"
      ? this.options.provider.evaluateL1(request.payload)
      : request.phase === "l2"
        ? this.options.provider.evaluateL2(request.payload)
        : this.evaluateL3(request.payload);
    try {
      return await Promise.race([evaluation, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private async evaluateL3(payload: YoloAutoPayload): Promise<YoloAutoL3Response> {
    if (!this.l3Ready) {
      this.l3Warmup ??= Promise.resolve(this.options.provider.warmL3?.()).then(
        () => { this.l3Ready = true; },
        (error: unknown) => {
          this.l3Warmup = undefined;
          throw error;
        },
      );
      await this.l3Warmup;
    }
    return this.options.provider.evaluateL3(payload);
  }

  private failedResponse(request: Partial<YoloAutoWorkerRequest>, error: string): YoloAutoWorkerResponse {
    return {
      requestId: request.requestId ?? "",
      phase: request.phase === "l1" ? "l1" : request.phase === "l3" ? "l3" : "l2",
      completion: "failed",
      error,
    };
  }

  private evictIfIdle(): void {
    if (this.busy || this.queue.length > 0 || this.sockets.size > 0) return;
    if (Date.now() - this.lastActivity < this.idleEvictionMs) return;
    void this.close();
  }
}
