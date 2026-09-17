import { lstatSync, unlinkSync } from "node:fs";
import { basename } from "node:path";

const PI_CLIPBOARD_FILENAME = /^pi-clipboard-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z0-9]+$/i;
const PI_CLIPBOARD_PATH_PATTERN = /\/[^\s"'`<>]*\/pi-clipboard-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[a-z0-9]+/gi;

export function extractPiClipboardPaths(text: string): string[] {
  return [...text.matchAll(PI_CLIPBOARD_PATH_PATTERN)].map(([path]) => path);
}

export interface PiClipboardTempCleanup {
  trackText(text: string): void;
  trackValue(value: unknown): void;
  reset(): void;
  cleanup(): void;
}

export function createPiClipboardTempCleanup(): PiClipboardTempCleanup {
  const paths = new Set<string>();

  const trackText = (text: string): void => {
    for (const path of extractPiClipboardPaths(text)) paths.add(path);
  };

  return {
    trackText,
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
    },
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
    },
  };
}
