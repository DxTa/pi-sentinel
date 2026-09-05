import { createGondolinOperations, type GondolinOperations } from "../gondolin-operations.js";
import {
  createGondolinSession,
  type GondolinGenerationState,
  type GondolinRuntime,
  type GondolinRuntimeSecret,
  type GondolinSession,
  type GondolinSessionPolicy,
} from "../gondolin-session.js";

export { GondolinOperationError } from "../gondolin-operations.js";
export type { GondolinOperations, GondolinOperationErrorCode } from "../gondolin-operations.js";

export type {
  GondolinRuntime,
  GondolinRuntimeCreateOptions,
  GondolinRuntimeSession,
  GondolinRuntimeOperations,
  GondolinRuntimeFileSystem,
  GondolinRuntimeSecret,
  GondolinVfsHooks,
  GondolinNetworkHooks,
  GondolinGenerationState,
} from "../gondolin-session.js";

export interface GondolinBackendOptions {
  runtime?: GondolinRuntime | null;
  runtimeFactory?: (options: {
    image: string | null | undefined;
    workspaceRoot: string | null | undefined;
    policy: GondolinSessionPolicy | null | undefined;
  }) => GondolinRuntime | null | undefined;
  image?: string | null;
  workspaceRoot?: string | null;
  policy?: GondolinSessionPolicy | null;
  secrets?: readonly GondolinRuntimeSecret[];
  environment?: Readonly<Record<string, string>>;
}

export type GondolinBackendSessionOptions = GondolinBackendOptions;

export interface GondolinBackend {
  readonly kind: "gondolin";
  createSession(options?: GondolinBackendSessionOptions): Promise<GondolinSession>;
  createOperations(session: GondolinSession): GondolinOperations;
}

/**
 * Gondolin backend with direct VM-backed Bash/read/write/edit adapters.
 */
export function createGondolinBackend(options: GondolinBackendOptions = {}): GondolinBackend {
  const generationState: GondolinGenerationState = { next: 0, current: 0 };
  return {
    kind: "gondolin",
    createOperations: createGondolinOperations,
    createSession(input: GondolinBackendSessionOptions = {}): Promise<GondolinSession> {
      const {
        runtime: inputRuntime,
        image = options.image,
        workspaceRoot = options.workspaceRoot,
        policy = options.policy,
        secrets = options.secrets,
        environment = options.environment,
      } = input;
      const runtime = inputRuntime ?? options.runtime ?? options.runtimeFactory?.({ image, workspaceRoot, policy });
      return createGondolinSession(
        { runtime, image, workspaceRoot, policy, secrets, runtimeEnvironment: environment },
        generationState,
      );
    },
  };
}
