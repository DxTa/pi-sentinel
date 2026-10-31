import { chmod, mkdir, rm, stat } from "node:fs/promises";
import { dirname } from "node:path";
import * as net from "node:net";

import { WORKER_HANDSHAKE_TIMEOUT_MS, WORKER_IDLE_EVICTION_MS } from "./auto-mode-client.ts";
import { withFileLock } from "./auto-mode-file-lock.ts";
import type { AutoModeHeads } from "./auto-mode-policy";

const AUTO_MODE_PROTOCOL_VERSION = 2;
const MAX_FRAME_BYTES = 1024 * 1024;
const DEFAULT_QUEUE_LIMIT = 32;

export type WorkerProvider = {
  ready(): Promise<void>;
  classify(text: string): Promise<AutoModeHeads>;
  close?(): Promise<void> | void;
};

export interface AutoModeWorkerServerOptions {
  socketPath: string;
  buildId: string;
  provider: WorkerProvider;
  queueLimit?: number;
  idleEvictionMs?: number;
}

interface ClassifyRequest {
  type: "classify";
  protocolVersion: typeof AUTO_MODE_PROTOCOL_VERSION;
  requestId: string;
  deadlineMs: number;
  text: string;
}

interface QueuedRequest {
  socket: net.Socket;
  request: ClassifyRequest;
  deadlineAt: number;
}

function isClassifyRequest(value: unknown): value is ClassifyRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const request = value as Record<string, unknown>;
  return request.type === "classify"
    && request.protocolVersion === AUTO_MODE_PROTOCOL_VERSION
    && typeof request.requestId === "string"
    && typeof request.deadlineMs === "number"
    && Number.isFinite(request.deadlineMs)
    && request.deadlineMs > 0
    && request.deadlineMs <= 10_000
    && typeof request.text === "string";
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

export class AutoModeWorkerServer {
  private readonly server = net.createServer((socket) => this.accept(socket));
  private readonly queue: QueuedRequest[] = [];
  private readonly sockets = new Set<net.Socket>();
  private readonly queueLimit: number;
  private readonly idleEvictionMs: number;
  private readonly options: AutoModeWorkerServerOptions;
  private readonly socketLockPath: string;
  private busy = false;
  private closing = false;
  private ownsSocket = false;
  private activeClassification: Promise<void> | undefined;
  private lastActivity = Date.now();
  private idleTimer: ReturnType<typeof setInterval> | undefined;
  private closePromise: Promise<void> | undefined;

  constructor(options: AutoModeWorkerServerOptions) {
    this.options = options;
    this.socketLockPath = options.socketPath + ".lock";
    this.queueLimit = options.queueLimit ?? DEFAULT_QUEUE_LIMIT;
    this.idleEvictionMs = options.idleEvictionMs ?? WORKER_IDLE_EVICTION_MS;
  }

  async start(): Promise<void> {
    await mkdir(dirname(this.options.socketPath), { recursive: true, mode: 0o700 });
    await chmod(dirname(this.options.socketPath), 0o700);
    await this.options.provider.ready();
    await withFileLock(this.socketLockPath, async () => {
      await removeStaleSocket(this.options.socketPath);
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
      this.ownsSocket = true;
      await chmod(this.options.socketPath, 0o600);
      this.idleTimer = setInterval(() => this.evictIfIdle(), 1000);
    });
  }

  close(): Promise<void> {
    this.closePromise ??= this.closeInternal();
    return this.closePromise;
  }

  private async closeInternal(): Promise<void> {
    this.closing = true;
    if (this.idleTimer) clearInterval(this.idleTimer);
    this.idleTimer = undefined;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    await this.activeClassification;
    const closeListener = () => new Promise<void>((resolve) => {
      if (!this.server.listening) {
        resolve();
        return;
      }
      this.server.close(() => resolve());
    });
    try {
      if (this.ownsSocket) {
        await withFileLock(this.socketLockPath, async () => {
          await closeListener();
          await rm(this.options.socketPath, { force: true });
          this.ownsSocket = false;
        });
      } else {
        await closeListener();
      }
    } finally {
      if (this.server.listening) await closeListener();
      await this.options.provider.close?.();
    }
  }

  private send(socket: net.Socket, value: unknown): void {
    try {
      socket.write(encodeFrame(value));
    } catch {
      socket.destroy();
    }
  }

  private accept(socket: net.Socket): void {
    if (this.closing) {
      socket.destroy();
      return;
    }
    this.sockets.add(socket);
    let buffer = Buffer.alloc(0);
    let handshaken = false;
    const handshakeTimer = setTimeout(() => socket.destroy(), WORKER_HANDSHAKE_TIMEOUT_MS);
    const failHandshake = (error: string): void => {
      this.send(socket, {
        type: "handshake",
        protocolVersion: AUTO_MODE_PROTOCOL_VERSION,
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
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        socket.destroy();
        return;
      }
      const message = parsed as Record<string, unknown>;
      if (!handshaken) {
        if (
          message.type !== "handshake"
          || message.protocolVersion !== AUTO_MODE_PROTOCOL_VERSION
        ) {
          failHandshake("unsupported_protocol");
          return;
        }
        handshaken = true;
        clearTimeout(handshakeTimer);
        this.send(socket, {
          type: "handshake",
          protocolVersion: AUTO_MODE_PROTOCOL_VERSION,
          status: "ready",
          buildId: this.options.buildId,
        });
        return;
      }
      if (message.type === "shutdown") {
        if (message.protocolVersion !== AUTO_MODE_PROTOCOL_VERSION) {
          socket.destroy();
          return;
        }
        socket.end();
        void this.close();
        return;
      }
      if (!isClassifyRequest(message)) {
        socket.destroy();
        return;
      }
      this.lastActivity = Date.now();
      if (this.queue.length >= this.queueLimit) {
        this.send(socket, this.failedResponse(message, "queue_overflow"));
        return;
      }
      this.queue.push({ socket, request: message, deadlineAt: Date.now() + message.deadlineMs });
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
        const remainingMs = entry.deadlineAt - this.lastActivity;
        if (remainingMs <= 0) {
          this.send(entry.socket, this.failedResponse(entry.request, "deadline_exceeded"));
          continue;
        }
        try {
          const heads = await this.evaluate(entry.request, remainingMs);
          if (Date.now() >= entry.deadlineAt) {
            this.send(entry.socket, this.failedResponse(entry.request, "deadline_exceeded"));
            continue;
          }
          if (!entry.socket.destroyed) {
            this.send(entry.socket, {
              type: "classify",
              protocolVersion: AUTO_MODE_PROTOCOL_VERSION,
              requestId: entry.request.requestId,
              status: "complete",
              heads,
            });
          }
        } catch (error) {
          if (!entry.socket.destroyed) {
            this.send(entry.socket, this.failedResponse(
              entry.request,
              Date.now() >= entry.deadlineAt
                ? "deadline_exceeded"
                : error instanceof Error ? error.message : String(error),
            ));
          }
          await this.activeClassification;
        }
      }
    } finally {
      this.busy = false;
    }
  }

  private async evaluate(request: ClassifyRequest, deadlineMs: number): Promise<AutoModeHeads> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const evaluation = Promise.resolve().then(() => this.options.provider.classify(request.text));
    const active = evaluation.then(() => undefined, () => undefined);
    this.activeClassification = active;
    void active.then(() => {
      if (this.activeClassification === active) this.activeClassification = undefined;
    });
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("deadline_exceeded")), deadlineMs);
    });
    try {
      return await Promise.race([evaluation, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private failedResponse(request: Pick<ClassifyRequest, "requestId">, error: string) {
    return {
      type: "classify" as const,
      protocolVersion: AUTO_MODE_PROTOCOL_VERSION,
      requestId: request.requestId,
      status: "failed" as const,
      error,
    };
  }

  private evictIfIdle(): void {
    if (this.busy || this.queue.length > 0 || this.sockets.size > 0) return;
    if (Date.now() - this.lastActivity < this.idleEvictionMs) return;
    void this.close();
  }
}
