import { X509Certificate } from 'node:crypto'
import { constants } from 'node:fs'
import { open } from 'node:fs/promises'

export function setDockerHostEnvironment(env, dockerHost) {
  if (!dockerHost) return
  delete env.DOCKER_CONTEXT
  env.DOCKER_HOST = dockerHost
}

export function certificateOnlyBundle(text) {
  const labels = [...text.matchAll(/-----BEGIN ([^-\r\n]+)-----/g)]
  if (!labels.length || labels.some((match) => match[1] !== 'CERTIFICATE')) return null
  const blocks = [...text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)]
  if (blocks.length !== labels.length) return null
  try {
    return blocks.map((block) => new X509Certificate(block[0]).toString().trimEnd()).join('\n') + '\n'
  } catch {
    return null
  }
}

export async function readTrustedCaBundle(path) {
  let file
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    const stat = await file.stat()
    if (!stat.isFile() || stat.size > 8 * 1024 * 1024) return null
    const data = Buffer.alloc(stat.size + 1)
    const { bytesRead } = await file.read(data, 0, data.length, 0)
    if (bytesRead !== stat.size) return null
    return certificateOnlyBundle(data.subarray(0, bytesRead).toString('utf8'))
  } catch {
    return null
  } finally {
    await file?.close()
  }
}
