const MAX_REPORTED_ENV_VARIABLES = 10;

export function summarizeEnvironmentSizes(env: NodeJS.ProcessEnv) {
  const variables = Object.entries(env)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string")
    .map(([name, value]) => ({
      name,
      bytes: Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8") + 2,
    }))
    .sort((left, right) => right.bytes - left.bytes || left.name.localeCompare(right.name));

  return {
    totalBytes: variables.reduce((total, variable) => total + variable.bytes, 0),
    largestVariables: variables.slice(0, MAX_REPORTED_ENV_VARIABLES),
  };
}
