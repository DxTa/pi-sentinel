import { open } from "node:fs/promises";
import { parseEnv } from "node:util";

const MASKED_VALUE = "****";
const MIN_SECRET_VALUE_LENGTH = 6;
const MAX_DOTENV_SOURCE_BYTES = 1024 * 1024;
const QUOTE_DELIMITER = /^["'`]$/;

interface DotenvAssignment {
  startLine: number;
  endLine: number;
  prefix: string;
  source: string;
}

function lineEnding(line: string): string {
  if (line.endsWith("\r\n")) return "\r\n";
  return line.endsWith("\n") ? "\n" : "";
}

function lineContent(line: string): string {
  const ending = lineEnding(line);
  return ending === "" ? line : line.slice(0, -ending.length);
}

function matchDotenvAssignment(content: string): { prefix: string; value: string } | null {
  const equalsIndex = content.indexOf("=");
  if (equalsIndex <= 0) return null;
  return {
    prefix: content.slice(0, equalsIndex + 1),
    value: content.slice(equalsIndex + 1),
  };
}

function findClosingQuote(value: string, quote: string, ignoreEscaped = false): number {
  let index = value.indexOf(quote);
  while (index !== -1) {
    let backslashes = 0;
    for (let cursor = index - 1; cursor >= 0 && value[cursor] === "\\"; cursor -= 1) {
      backslashes += 1;
    }
    if (!ignoreEscaped || backslashes % 2 === 0) return index;
    index = value.indexOf(quote, index + 1);
  }
  return -1;
}

function scanDotenvAssignments(
  text: string,
  failClosedOnUnclosedQuote = false,
): { lines: string[]; assignments: DotenvAssignment[] } {
  const lines = text.split(/(?<=\n)/);
  const assignments: DotenvAssignment[] = [];

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const content = lineContent(lines[lineIndex]!);
    if (content.trimStart().startsWith("#")) continue;

    const match = matchDotenvAssignment(content);
    if (!match) continue;

    const value = match.value.trimStart();
    let quoteLine = lineIndex;
    let quotedValue = value;
    let quote = value[0];

    if (!quote) {
      let candidateLine = lineIndex + 1;
      while (candidateLine < lines.length && lineContent(lines[candidateLine]!).trim() === "") {
        candidateLine += 1;
      }
      const candidateValue = candidateLine < lines.length
        ? lineContent(lines[candidateLine]!).trimStart()
        : "";
      if (QUOTE_DELIMITER.test(candidateValue[0] ?? "")) {
        quoteLine = candidateLine;
        quotedValue = candidateValue;
        quote = candidateValue[0];
      }
    }

    let endLine = lineIndex;
    if (quote && QUOTE_DELIMITER.test(quote)) {
      endLine = quoteLine;
      if (findClosingQuote(quotedValue.slice(1), quote, failClosedOnUnclosedQuote) === -1) {
        let foundClosingQuote = false;
        for (let candidateLine = quoteLine + 1; candidateLine < lines.length; candidateLine += 1) {
          if (findClosingQuote(lineContent(lines[candidateLine]!), quote, failClosedOnUnclosedQuote) !== -1) {
            endLine = candidateLine;
            foundClosingQuote = true;
            break;
          }
        }
        if (failClosedOnUnclosedQuote && !foundClosingQuote) endLine = lines.length - 1;
      }
    }

    assignments.push({
      startLine: lineIndex,
      endLine,
      prefix: match.prefix,
      source: lines.slice(lineIndex, endLine + 1).join(""),
    });
    lineIndex = endLine;
  }

  return { lines, assignments };
}

function isSafeVisibleAssignmentPrefix(prefix: string): boolean {
  const match = prefix.match(/^\uFEFF?[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=$/);
  if (!match) return false;

  const name = match[1]!;
  return /^[A-Z_][A-Z0-9_.-]*$/.test(name)
    || /^[a-z_][a-z0-9_.-]*$/.test(name);
}

export function maskDotenvText(text: string): string {
  const { lines, assignments } = scanDotenvAssignments(text, true);
  const maskedLines = [...lines];
  const handledLines = new Set<number>();

  for (const assignment of assignments) {
    const firstLineContent = lineContent(lines[assignment.startLine]!);
    const value = firstLineContent.slice(assignment.prefix.length).trimStart();
    const hasValue = value !== "" || assignment.endLine > assignment.startLine;
    const exposeName = isSafeVisibleAssignmentPrefix(assignment.prefix)
      && hasValue
      && !value.startsWith("=");
    const firstLine = exposeName ? `${assignment.prefix}${MASKED_VALUE}` : MASKED_VALUE;

    for (let lineIndex = assignment.startLine; lineIndex <= assignment.endLine; lineIndex += 1) {
      handledLines.add(lineIndex);
      maskedLines[lineIndex] = `${lineIndex === assignment.startLine ? firstLine : MASKED_VALUE}${lineEnding(lines[lineIndex]!)}`;
    }
  }

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const content = lineContent(lines[lineIndex]!);
    const ending = lineEnding(lines[lineIndex]!);
    if (handledLines.has(lineIndex)) continue;
    if (content.trim() === "") continue;

    const commentPrefix = content.match(/^\uFEFF?[ \t\r]*#/);
    if (commentPrefix) {
      maskedLines[lineIndex] = `${commentPrefix[0]} ${MASKED_VALUE}${ending}`;
      continue;
    }

    const assignment = matchDotenvAssignment(content);
    const value = assignment?.value.trimStart() ?? "";
    const exposeName = assignment !== null
      && isSafeVisibleAssignmentPrefix(assignment.prefix)
      && value !== ""
      && !value.startsWith("=");
    maskedLines[lineIndex] = `${exposeName ? `${assignment.prefix}${MASKED_VALUE}` : MASKED_VALUE}${ending}`;
  }

  return maskedLines.join("");
}

export async function readDotenvSourceWithinLimit(filePath: string): Promise<string | null> {
  const handle = await open(filePath, "r");
  try {
    const buffer = Buffer.alloc(MAX_DOTENV_SOURCE_BYTES + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    if (bytesRead > MAX_DOTENV_SOURCE_BYTES) return null;
    return buffer.toString("utf8", 0, bytesRead);
  } finally {
    await handle.close();
  }
}

export function maskDotenvReadResult(
  resultText: string,
  sourceText: string,
  startLine: number,
  outputLineCount: number,
): string {
  if (
    !Number.isInteger(startLine) || startLine < 0
    || !Number.isInteger(outputLineCount) || outputLineCount < 0
  ) {
    return MASKED_VALUE;
  }

  const resultLines = resultText.split("\n");
  const sourceLines = sourceText.split("\n");
  const maskedSourceLines = maskDotenvText(sourceText).split("\n");

  for (let outputLine = 0; outputLine < outputLineCount; outputLine += 1) {
    const sourceLine = startLine + outputLine;
    if (sourceLines[sourceLine] === undefined || resultLines[outputLine] !== sourceLines[sourceLine]) {
      return MASKED_VALUE;
    }
    resultLines[outputLine] = maskedSourceLines[sourceLine]!;
  }

  const isReadContinuation = (line: string): boolean => line === ""
    || /^\[\d+ more lines in file\. Use offset=\d+ to continue\.\]$/.test(line)
    || /^\[Showing lines \d+-\d+ of \d+(?: \([^\]\r\n]+\))?\. Use offset=\d+ to continue\.\]$/.test(line)
    || /^\[Line \d+ is .+, exceeds .+ limit\. Use bash: .+\]$/.test(line);
  if (resultLines.slice(outputLineCount).some((line) => !isReadContinuation(line))) {
    return MASKED_VALUE;
  }

  return resultLines.join("\n");
}

export function maskSecretValues(text: string, values: readonly string[]): string {
  // shortcut: exact scanning skips short values to avoid masking common text; assignment lines are masked separately.
  const uniqueLongValues = [...new Set(values.filter((value) => value.length >= MIN_SECRET_VALUE_LENGTH))]
    .sort((left, right) => right.length - left.length);
  return uniqueLongValues.reduce((result, value) => result.replaceAll(value, MASKED_VALUE), text);
}

export async function parseDotenvValues(filePath: string): Promise<string[]> {
  const text = await readDotenvSourceWithinLimit(filePath);
  if (text === null) throw new Error("dotenv source exceeds the 1 MiB masking limit");
  const { assignments } = scanDotenvAssignments(text);
  // Parse each assignment separately so duplicate keys remain available for masking.
  return assignments.flatMap(({ source }) =>
    Object.values(parseEnv(source)).filter((value): value is string => value !== undefined),
  );
}
