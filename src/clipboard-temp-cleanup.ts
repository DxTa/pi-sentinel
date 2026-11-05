import { lstatSync, realpathSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename } from "node:path";

import { isPathWithinDirectory } from "#src/path-utils";

const PI_CLIPBOARD_FILENAME = /^pi-clipboard-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z0-9]+$/i;
const PI_CLIPBOARD_PATH_PATTERN = /\/[^\s"'`<>]*\/pi-clipboard-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z0-9]+/gi;

export function extractPiClipboardPaths(text: string): string[] {
  return [...text.matchAll(PI_CLIPBOARD_PATH_PATTERN)].map(([path]) => path);
}

/**
 * Temp roots pi writes clipboard files to. macOS puts them in the per-user `/var/folders/<x>/<y>/T`,
 * which differs from `os.tmpdir()` whenever `TMPDIR` is overridden.
 */
const PI_CLIPBOARD_TEMP_ROOTS = [
  /^\/private\/var\/folders\/[^/]+\/[^/]+\/T\//,
  /^\/private\/tmp\//,
  /^\/private\/var\/tmp\//,
];

/** Canonical path lies in `os.tmpdir()` or a known pi clipboard temp root. */
export function isInsidePiClipboardTempRoot(canonicalPath: string): boolean {
  return isPathWithinDirectory(canonicalPath, realpathSync.native(tmpdir()))
    || PI_CLIPBOARD_TEMP_ROOTS.some((root) => root.test(canonicalPath));
}

/**
 * A regular `pi-clipboard-<UUID>.<ext>` file in a pi clipboard temp root. Symlinks and hard links are
 * refused: a link to a secret elsewhere would otherwise inherit the trusted name and location.
 */
export function isPiClipboardTempFile(path: string): boolean {
  if (!PI_CLIPBOARD_FILENAME.test(basename(path))) return false;
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) return false;
    return isInsidePiClipboardTempRoot(realpathSync.native(path));
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
