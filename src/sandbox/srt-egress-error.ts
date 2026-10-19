export function srtEgressFailureMessage(output: string): string | undefined {
  if (!/socat(?:\[\d+\])?.*proxy_connect: connection closed by proxy/is.test(output)) {
    return undefined;
  }
  return "Sandbox network egress failed because its proxy closed the connection. The command was not retried automatically; check the sandbox proxy and retry.";
}
