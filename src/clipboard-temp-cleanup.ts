import { lstatSync, realpathSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename } from "node:path";

import { isPathWithinDirectory } from "#src/path-utils";

const PI_CLIPBOARD_FILENAME = /^pi-clipboard-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z0-9]+$/i;
const PI_CLIPBOARD_PATH_PATTERN = /\/[^\s"'`<>]*\/pi-clipboard-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z0-9]+/gi;

export function extractPiClipboardPaths(text: string): string[] {
  return [...text.matchAll(PI_CLIPBOARD_PATH_PATTERN)].map(([path]) => path);
}

/** A regular (non-symlink) `pi-clipboard-<UUID>.<ext>` file inside the OS temp root. */
export function isPiClipboardTempFile(path: string): boolean {
  if (!PI_CLIPBOARD_FILENAME.test(basename(path))) return false;
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) return false;
    return isPathWithinDirectory(realpathSync.native(path), realpathSync.native(tmpdir()));
  } catch {
    return false;
  }
}

export interface PiClipboardTempCleanup {
  trackText(text: string): void;
  trackInteractiveText(text: string): void;
  trackValue(value: unknown): void;
  isTrackedInteractivePath(path: string): boolean;
  reset(): void;
  cleanup(): void;
}

export function createPiClipboardTempCleanup(): PiClipboardTempCleanup {
  const paths = new Set<string>();
  const interactivePaths = new Set<string>();

  const recordPaths = (text: string, trustedPaths?: Set<string>): void => {
    for (const path of extractPiClipboardPaths(text)) {
      paths.add(path);
      trustedPaths?.add(path);
    }
  };

  const trackText = (text: string): void => {
    recordPaths(text);
  };

  const trackInteractiveText = (text: string): void => {
    recordPaths(text, interactivePaths);
  };

  const isTrackedInteractivePath = (path: string): boolean => {
    return interactivePaths.has(path) && isPiClipboardTempFile(path);
  };

  return {
    trackText,
    trackInteractiveText,
    trackValue(value) {
      if (typeof value === "string") {
        trackText(value);
        return;
      }
      try {
        const serialized = JSON.stringify(value);
        if (serialized) trackText(serialized);
      } catch {
        // Ignore non-serializable tool inputs.
      }
    },
    reset() {
      paths.clear();
      interactivePaths.clear();
    },
    isTrackedInteractivePath,
    cleanup() {
      for (const path of paths) {
        try {
          const stat = lstatSync(path);
          if (stat.isFile() && !stat.isSymbolicLink() && PI_CLIPBOARD_FILENAME.test(basename(path))) {
            unlinkSync(path);
          }
        } catch {
          // Temp files may already be gone or inaccessible.
        }
      }
      paths.clear();
      interactivePaths.clear();
    },
  };
}
