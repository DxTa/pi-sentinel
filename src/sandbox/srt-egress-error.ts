export function srtEgressFailureMessage(output: string, hostFallbackAvailable = false): string | undefined {
  if (!/socat(?:\[\d+\])?.*proxy_connect: connection closed by proxy/is.test(output)) {
    return undefined;
  }
  const summary = "Sandbox network egress failed because its proxy closed the connection. The command was not retried automatically.";
  return hostFallbackAvailable
    ? summary + "\n\nONE-TIME HOST FALLBACK IS AVAILABLE. To request explicit user approval, call Bash again with the exact original command in the same working directory and Pi session. The next call will show Allow once / Deny for execution outside SRT. Do not change the command, restart Pi, or bypass approval."
    : summary + " Host fallback is unavailable. Check the sandbox proxy before retrying.";
}
