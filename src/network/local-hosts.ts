/* Hosts that stay on this machine or its container/VM host. Judged by name, so no DNS lookup happens.
 * shortcut: /etc/hosts entries that point at loopback are not recognised, only the reserved .localhost names. */
const LOCAL_NAMES = new Set(["localhost", "host.docker.internal", "host.lima.internal", "kubernetes.docker.internal"]);
const IPV4_LOOPBACK = /^127(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function isLocalHost(host: string): boolean {
  const name = host.toLowerCase().replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "");
  return name === "::1"
    || IPV4_LOOPBACK.test(name)
    || LOCAL_NAMES.has(name)
    || name.endsWith(".localhost");
}
