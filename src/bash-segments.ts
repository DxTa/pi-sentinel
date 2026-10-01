/**
 * Split a Bash command into simple segments on control operators
 * (&&, ||, ;, |, newline). Returns null when the command contains command or
 * process substitution, whose inner commands cannot be matched by prefix rules.
 * Quoted operators over-split, which only makes matching stricter.
 */
const SUBSTITUTION = /\$\(|`|<\(|>\(/;
const CONTROL_OPERATOR = /&&|\|\||[;|\n]/;

export function splitBashSegments(command: string): string[] | null {
  if (SUBSTITUTION.test(command)) return null;
  return command.split(CONTROL_OPERATOR).map((segment) => segment.trim()).filter(Boolean);
}
