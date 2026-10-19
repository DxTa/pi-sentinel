import { basename, isAbsolute, resolve } from "node:path";

import { bashLiteralWord, bashWords, scanQuotes } from "../bash-segments";
import { matchesGitPushCommand } from "../yolo-mode";

/** Host fallback is narrower than push detection: one direct, fully literal command. */
export function literalGitPushKey(command: string, cwd: string): string | undefined {
  const scan = scanQuotes(command);
  if (!scan || /[\r\n;&|<>()]/.test(scan.masked)) return undefined;
  const words = bashWords(command);
  if (!words?.length || words.some((word) => bashLiteralWord(word) === null)) return undefined;
  const executable = bashLiteralWord(words[0])!;
  if (executable !== "git" && !(isAbsolute(executable) && basename(executable) === "git")) return undefined;
  if (!matchesGitPushCommand(command)) return undefined;
  return JSON.stringify([resolve(cwd), command]);
}
