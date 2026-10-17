export function setDockerHostEnvironment(env, dockerHost) {
  if (!dockerHost) return
  delete env.DOCKER_CONTEXT
  env.DOCKER_HOST = dockerHost
}
