import { realpathSync } from "node:fs";
import { extname, isAbsolute, posix, relative, resolve, sep } from "node:path";
import type {
  BashOperations,
  EditOperations,
  ReadOperations,
  WriteOperations,
} from "@earendil-works/pi-coding-agent";

import type {
  GondolinRuntimeOperations,
  GondolinSession,
} from "./gondolin-session.js";

export type GondolinOperationErrorCode = "session-unavailable" | "closed" | "denied";

export class GondolinOperationError extends Error {
  readonly code: GondolinOperationErrorCode;

  constructor(code: GondolinOperationErrorCode, message: string) {
    super(message);
    this.name = "GondolinOperationError";
    this.code = code;
  }
}

export interface GondolinEditPreview {
  readonly mode: "display-only";
  readonly path: string;
  readonly content: string;
}

export interface GondolinEditOperations extends EditOperations {
  preview(inputPath: string, content: string): Promise<GondolinEditPreview>;
}

export interface GondolinOperations {
  readonly bash: BashOperations;
  readonly read: ReadOperations;
  readonly write: WriteOperations;
  readonly edit: GondolinEditOperations;
}

const GUEST_WORKSPACE = "/workspace";

function assertSession(session: GondolinSession): GondolinRuntimeOperations {
  if (session.closed) {
    throw new GondolinOperationError("closed", "Gondolin session is closed.");
  }
  if (!session.operations) {
    throw new GondolinOperationError(
      "session-unavailable",
      "Gondolin VM operation surface is unavailable.",
    );
  }
  return session.operations;
}

function hostPath(session: GondolinSession, inputPath: string): string {
  if (typeof inputPath !== "string" || inputPath.trim() === "" || inputPath.includes("\u0000")) {
    throw new GondolinOperationError("denied", "Gondolin operation path is invalid.");
  }
  return isAbsolute(inputPath) ? resolve(inputPath) : resolve(session.workspaceRoot, inputPath);
}

function guestPath(session: GondolinSession, inputPath: string): string {
  const absolutePath = hostPath(session, inputPath);
  let workspaceRoot: string;
  try {
    workspaceRoot = realpathSync.native(resolve(session.workspaceRoot));
  } catch {
    workspaceRoot = resolve(session.workspaceRoot);
  }
  const relativePath = relative(workspaceRoot, absolutePath);
  if (
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  ) {
    throw new GondolinOperationError("denied", "Gondolin operation path is outside the approved workspace.");
  }
  return relativePath
    ? posix.join(GUEST_WORKSPACE, relativePath.split(sep).join("/"))
    : GUEST_WORKSPACE;
}

function requireAllowed(
  result: { decision: string; reason: string },
  path: string,
): void {
  if (result.decision !== "allow" && result.decision !== "placeholder") {
    throw new GondolinOperationError("denied", `${result.reason} (${path})`);
  }
}

function authorizeRead(session: GondolinSession, inputPath: string): { path: string; masked: boolean } {
  const absolutePath = hostPath(session, inputPath);
  const result = session.vfs.read({ operation: "read", path: absolutePath });
  requireAllowed(result, absolutePath);
  return { path: result.path ?? absolutePath, masked: result.decision === "placeholder" };
}

function authorizeMutation(session: GondolinSession, inputPath: string): string {
  const absolutePath = hostPath(session, inputPath);
  const result = session.vfs.mutate({ operation: "write", path: absolutePath });
  if (result.decision !== "allow") {
    throw new GondolinOperationError("denied", `${result.reason} (${absolutePath})`);
  }
  return result.path ?? absolutePath;
}

async function accessAuthorizedRead(session: GondolinSession, inputPath: string): Promise<void> {
  const operations = assertSession(session);
  const authorized = authorizeRead(session, inputPath);
  if (authorized.masked) return;
  await operations.fs.access(guestPath(session, authorized.path));
}

function createReadOperations(session: GondolinSession): ReadOperations {
  return {
    access: (inputPath) => accessAuthorizedRead(session, inputPath),
    readFile: async (inputPath) => {
      const operations = assertSession(session);
      const authorized = authorizeRead(session, inputPath);
      if (authorized.masked) return Buffer.from("(masked)");
      return operations.fs.readFile(guestPath(session, authorized.path));
    },
    detectImageMimeType: async (inputPath) => {
      assertSession(session);
      const authorized = authorizeRead(session, inputPath);
      if (authorized.masked) return null;
      const extension = extname(guestPath(session, authorized.path)).toLowerCase();
      if (extension === ".png") return "image/png";
      if (extension === ".jpg" || extension === ".jpeg") return "image/jpeg";
      if (extension === ".gif") return "image/gif";
      if (extension === ".webp") return "image/webp";
      if (extension === ".bmp") return "image/bmp";
      return null;
    },
  };
}

async function writeAuthorizedFile(
  session: GondolinSession,
  inputPath: string,
  content: string,
): Promise<void> {
  const operations = assertSession(session);
  const authorizedPath = authorizeMutation(session, inputPath);
  await operations.fs.writeFile(guestPath(session, authorizedPath), content);
}

function createWriteOperations(session: GondolinSession): WriteOperations {
  return {
    writeFile: (inputPath, content) => writeAuthorizedFile(session, inputPath, content),
    mkdir: async (inputPath) => {
      const operations = assertSession(session);
      const authorizedPath = authorizeMutation(session, inputPath);
      await operations.fs.mkdir(guestPath(session, authorizedPath), { recursive: true });
    },
  };
}

function createEditOperations(session: GondolinSession): GondolinEditOperations {
  return {
    access: (inputPath) => accessAuthorizedRead(session, inputPath),
    readFile: async (inputPath) => {
      const operations = assertSession(session);
      const authorized = authorizeRead(session, inputPath);
      if (authorized.masked) return Buffer.from("(masked)");
      const vmPath = guestPath(session, authorized.path);
      await operations.fs.access(vmPath);
      return operations.fs.readFile(vmPath);
    },
    writeFile: (inputPath, content) => writeAuthorizedFile(session, inputPath, content),
    preview: async (inputPath, content) => {
      assertSession(session);
      const authorized = authorizeRead(session, inputPath);
      if (authorized.masked) {
        throw new GondolinOperationError("denied", "Sensitive edit preview is denied.");
      }
      return {
        mode: "display-only",
        path: guestPath(session, authorized.path),
        content,
      };
    },
  };
}

function createBashOperations(session: GondolinSession): BashOperations {
  return {
    exec: async (command, cwd, options) => {
      const operations = assertSession(session);
      const authorizedCwd = authorizeRead(session, cwd || session.workspaceRoot);
      if (authorizedCwd.masked) {
        throw new GondolinOperationError("denied", "Gondolin bash working directory is masked.");
      }
      return operations.exec(command, guestPath(session, authorizedCwd.path), options);
    },
  };
}

/** Build the strict direct-tool operation set for one active Gondolin policy session. */
export function createGondolinOperations(session: GondolinSession): GondolinOperations {
  return {
    bash: createBashOperations(session),
    read: createReadOperations(session),
    write: createWriteOperations(session),
    edit: createEditOperations(session),
  };
}
