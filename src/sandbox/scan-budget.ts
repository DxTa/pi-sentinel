export const DEFAULT_SCAN_DURATION_MS = 2_000;

export class ScanBudgetExceededError extends Error {
  constructor(
    readonly durationMs: number,
    readonly currentPath: string,
  ) {
    super(`Sandbox filesystem preparation exceeded ${durationMs} ms at ${currentPath}`);
    this.name = "ScanBudgetExceededError";
  }
}

export function assertScanWithinBudget(
  deadline: number,
  durationMs: number,
  currentPath: string,
): void {
  if (Date.now() >= deadline) {
    throw new ScanBudgetExceededError(durationMs, currentPath);
  }
}

export async function awaitWithinScanBudget<T>(
  operation: Promise<T>,
  deadline: number,
  durationMs: number,
  currentPath: string,
): Promise<T> {
  const remainingMs = deadline - Date.now();
  assertScanWithinBudget(deadline, durationMs, currentPath);

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new ScanBudgetExceededError(durationMs, currentPath)),
          remainingMs,
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function isScanBudgetExceeded(error: unknown): error is ScanBudgetExceededError {
  return error instanceof ScanBudgetExceededError;
}
