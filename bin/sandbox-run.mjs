#!/usr/bin/env node
import { execFileSync, spawn } from 'node:child_process'
import { chmod, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'

const ENV_KEY = 'PI_SRT_HELPER_INPUT_B64'
const MASK_MAP_ENV = 'PI_SRT_MASK_MAP_B64'
const INTERNAL_ENV_NAMES = new Set([
  ENV_KEY,
  MASK_MAP_ENV,
  'PI_SRT_OPERATION_PAYLOAD_B64',
])
const SRT_RUNTIME_ENV_NAMES = new Set([
  'SANDBOX_RUNTIME',
  'TMPDIR',
  'NO_PROXY',
  'no_proxy',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'http_proxy',
  'https_proxy',
  'ALL_PROXY',
  'all_proxy',
  'FTP_PROXY',
  'ftp_proxy',
  'RSYNC_PROXY',
  'GIT_CONFIG_PARAMETERS',
  'GIT_SSH_COMMAND',
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'CURL_CA_BUNDLE',
  'REQUESTS_CA_BUNDLE',
  'PIP_CERT',
  'GIT_SSL_CAINFO',
  'AWS_CA_BUNDLE',
  'CARGO_HTTP_CAINFO',
  'DENO_CERT',
])
const REAL_COMMANDS = {
  cat: '/bin/cat',
  head: '/usr/bin/head',
  tail: '/usr/bin/tail',
  grep: '/usr/bin/grep',
  // Direct-file masked UX shim: approximate `rg pattern file` via system grep.
  // Full ripgrep parity needs broader executable/toolchain allowlisting.
  rg: '/usr/bin/grep',
}

function decodeHelperInput() {
  const encoded = process.env[ENV_KEY]
  if (!encoded) {
    throw new Error(`${ENV_KEY} is not set`)
  }
  return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'))
}

function createUnmatchedHostCallback(helperInput) {
  if (helperInput.unmatchedHostAction === 'allow') {
    return async () => true
  }
  return async () => false
}

function matchesEnvPattern(name, pattern) {
  const escaped = String(pattern).replace(/[|\\{}()[\]^$+?.]/g, '\\$&')
  return new RegExp(`^${escaped.replace(/\*/g, '.*')}$`).test(name)
}

function isProtectedEnvironmentName(name) {
  return /(?:TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)/i.test(name)
}

function filterChildEnvironment(helperInput, env, generatedRuntimeEnvNames = new Set()) {
  const allow = Array.isArray(helperInput.envAllowPatterns) ? helperInput.envAllowPatterns : []
  const deny = Array.isArray(helperInput.envDenyPatterns) ? helperInput.envDenyPatterns : []
  const filtered = {}
  for (const [name, value] of Object.entries(env)) {
    if (INTERNAL_ENV_NAMES.has(name)) {
      filtered[name] = value
      continue
    }
    if (isProtectedEnvironmentName(name)) continue
    if (generatedRuntimeEnvNames.has(name) && SRT_RUNTIME_ENV_NAMES.has(name)) {
      filtered[name] = value
      continue
    }
    if (allow.length > 0 && !allow.some((pattern) => matchesEnvPattern(name, pattern))) continue
    if (deny.some((pattern) => matchesEnvPattern(name, pattern))) continue
    filtered[name] = value
  }
  return filtered
}

function shellSingleQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

function resolveRealCommand(commandName) {
  const configured = REAL_COMMANDS[commandName]
  if (configured) return configured
  try {
    return execFileSync('/bin/sh', ['-lc', `command -v ${commandName}`], { encoding: 'utf8' }).trim()
  } catch {
    return null
  }
}

async function canonicalizeApprovedPaths(unmaskedPaths) {
  const approved = new Set()
  for (const entry of Array.isArray(unmaskedPaths) ? unmaskedPaths : []) {
    const rawPath = entry && typeof entry.path === 'string' ? entry.path : null
    if (!rawPath) continue
    approved.add(rawPath)
    try {
      approved.add(await realpath(rawPath))
    } catch {
      // Path may disappear between planning and execution; keep raw path.
    }
  }
  return approved
}

async function prepareShims(helperInput) {
  const plan = helperInput.maskedShimPlan
  const execShimPlan = helperInput.execShimPlan && typeof helperInput.execShimPlan === 'object'
    ? helperInput.execShimPlan
    : {}
  const approvedUnmasked = await canonicalizeApprovedPaths(helperInput.unmaskedPaths)
  const filteredMaskedFilePaths = Array.isArray(plan?.maskedFilePaths)
    ? plan.maskedFilePaths.filter((path) => !approvedUnmasked.has(path))
    : []
  const needsMaskedShims = filteredMaskedFilePaths.length > 0
  const needsExecShims = Object.keys(execShimPlan).length > 0
  if (!needsMaskedShims && !needsExecShims) {
    return { env: {}, cleanup: async () => {} }
  }

  const rootPath = await mkdtemp(join(tmpdir(), 'pi-srt-shim-'))
  try {
    const root = await realpath(rootPath)
    const actualPlaceholderDir = await realpath(await mkdtemp(join(root, 'placeholder-files-')))
  const actualShimDir = await realpath(await mkdtemp(join(root, 'shim-bin-')))
  const maskMap = {}

  if (needsMaskedShims) {
    for (const originalPath of filteredMaskedFilePaths) {
      let canonicalPath = originalPath
      try {
        canonicalPath = await realpath(originalPath)
      } catch {
        // Keep original path if the host path disappeared after planning.
      }
      if (approvedUnmasked.has(originalPath) || approvedUnmasked.has(canonicalPath)) {
        continue
      }
      const placeholderPath = join(actualPlaceholderDir, `${Object.keys(maskMap).length}-${basename(canonicalPath) || 'masked'}`)
      await writeFile(placeholderPath, '(masked)\n', 'utf8')
      maskMap[originalPath] = placeholderPath
      maskMap[canonicalPath] = placeholderPath
      helperInput.runtimeConfig.filesystem.denyRead.push(originalPath, canonicalPath)
      helperInput.runtimeConfig.filesystem.denyWrite.push(originalPath, canonicalPath)
    }
  }

  helperInput.runtimeConfig.filesystem.allowRead.push(actualPlaceholderDir, actualShimDir)

  const cases = Object.entries(maskMap)
    .map(([realPath, placeholderPath]) => `    ${shellSingleQuote(realPath)}) replacement=${shellSingleQuote(placeholderPath)} ;;`)
    .join('\n')

  async function writeReaderShim(commandName) {
    const realCommand = resolveRealCommand(commandName)
    if (!realCommand) return
    helperInput.runtimeConfig.filesystem.allowRead.push(realCommand)
    const shimPath = join(actualShimDir, commandName)
    await writeFile(shimPath, `#!/bin/sh
# Minimal masked reader shim. SRT still denies real masked files if this shim is bypassed.
real_cmd=${shellSingleQuote(realCommand)}
mapped_args=""
append_arg() {
  escaped=$(printf '%s\n' "$1" | sed "s/'/'\\\\''/g")
  mapped_args="$mapped_args '$escaped'"
}
for arg in "$@"; do
  case "$arg" in
    -*) append_arg "$arg"; continue ;;
    /*) abs="$arg" ;;
    *)
      dir=$(dirname "$arg")
      base=$(basename "$arg")
      abs="$(cd "$dir" 2>/dev/null && pwd -P)/$base"
      ;;
  esac
  replacement=""
  case "\${abs:-$arg}" in
${cases}
    *) ;;
  esac
  if [ -n "$replacement" ]; then
    append_arg "$replacement"
  else
    append_arg "$arg"
  fi
  unset abs replacement
done
eval "exec $real_cmd $mapped_args"
`, 'utf8')
    await chmod(shimPath, 0o755)
  }

  async function writeExecShim(commandName, realCommand) {
    if (!realCommand) return
    helperInput.runtimeConfig.filesystem.allowRead.push(realCommand)
    const shimPath = join(actualShimDir, commandName)
    const prelude = commandName === 'git'
      ? 'export GIT_CONFIG_NOSYSTEM=1\n'
      : ''
    await writeFile(shimPath, `#!/bin/sh
${prelude}exec ${shellSingleQuote(realCommand)} "$@"
`, 'utf8')
    await chmod(shimPath, 0o755)
  }

  for (const [commandName, realCommand] of Object.entries(execShimPlan)) {
    await writeExecShim(commandName, realCommand)
  }

  if (needsMaskedShims && Array.isArray(plan.shimCommands)) {
    for (const commandName of plan.shimCommands) {
      await writeReaderShim(commandName)
    }
  }

    return {
      env: {
        PATH: `${actualShimDir}:${process.env.PATH || ''}`,
        [MASK_MAP_ENV]: Buffer.from(JSON.stringify(maskMap), 'utf8').toString('base64'),
      },
      cleanup: async () => {
        await rm(rootPath, { recursive: true, force: true })
      },
    }
  } catch (error) {
    await rm(rootPath, { recursive: true, force: true })
    throw error
  }
}

function killProcessGroup(pid, signal) {
  if (!pid || process.platform === 'win32') return
  try {
    process.kill(-pid, signal)
  } catch {
    // The process group may already be gone.
  }
}

async function terminateProcessGroup(pid) {
  if (!pid) return
  killProcessGroup(pid, 'SIGTERM')
  await new Promise((resolve) => setTimeout(resolve, 25))
  killProcessGroup(pid, 'SIGKILL')
}

async function runChild(argv, cwd, env) {
  let child
  const forwardSignal = (signal) => {
    if (!child) return
    killProcessGroup(child.pid, signal)
    child.kill(signal)
  }
  process.on('SIGTERM', forwardSignal)
  process.on('SIGINT', forwardSignal)
  try {
    const exitCode = await new Promise((resolve, reject) => {
      child = spawn(argv[0], argv.slice(1), {
        cwd,
        env,
        stdio: 'inherit',
        detached: process.platform !== 'win32',
      })
      child.on('close', (code) => resolve(code ?? 1))
      child.on('error', reject)
    })
    await terminateProcessGroup(child.pid)
    return Number(exitCode)
  } finally {
    process.off('SIGTERM', forwardSignal)
    process.off('SIGINT', forwardSignal)
  }
}

async function main() {
  const helperInput = decodeHelperInput()
  let mod
  try {
    mod = await import('@anthropic-ai/sandbox-runtime')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Failed to load @anthropic-ai/sandbox-runtime: ${message}`)
  }

  const { SandboxManager } = mod
  if (!SandboxManager) {
    throw new Error('SandboxManager export missing from @anthropic-ai/sandbox-runtime')
  }

  let shim = { env: {}, cleanup: async () => {} }
  try {
    shim = await prepareShims(helperInput)
    const { dockerHost, ...runtimeConfig } = helperInput.runtimeConfig
    await SandboxManager.initialize(runtimeConfig, createUnmatchedHostCallback(helperInput))
    const wrapped = await SandboxManager.wrapWithSandboxArgv(helperInput.command)
    const wrappedEnv = wrapped.env ?? {}
    const env = filterChildEnvironment(
      helperInput,
      { ...process.env, ...wrappedEnv, ...shim.env },
      new Set(Object.keys(wrappedEnv)),
    )
    if (dockerHost) env.DOCKER_HOST = dockerHost
    return await runChild(wrapped.argv, helperInput.cwd, env)
  } finally {
    try {
      if (typeof SandboxManager.reset === 'function') {
        await SandboxManager.reset()
      }
    } finally {
      await shim.cleanup()
    }
  }
}

main().then((exitCode) => {
  process.exitCode = exitCode
}).catch((error) => {
  const message = error instanceof Error ? error.message : String(error)
  process.stderr.write(`sandbox-run error: ${message}\n`)
  process.exitCode = 1
})
