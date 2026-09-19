import { describe, expect, it, vi } from "vitest";

import {
  YoloAutoClient,
  type YoloAutoWorkerRequest,
  type YoloAutoWorkerResponse,
  type YoloAutoWorkerTransport,
} from "./yolo-auto-client";

const payload = {
  toolName: "read_file",
  operation: "read",
  workspaceRelativePath: "src/index.ts",
};

function response(
  request: YoloAutoWorkerRequest,
  overrides: Partial<YoloAutoWorkerResponse> = {},
): YoloAutoWorkerResponse {
  return {
    requestId: request.requestId,
    phase: request.phase,
    completion: "complete",
    l1: { verdict: "safe", accepted: true, complete: true, degraded: false },
    l2: { results: [], escalated: false },
    ...overrides,
  };
}

describe("YoloAutoClient", () => {
  it("runs L1 before one non-escalated L2 request", async () => {
    const requests: YoloAutoWorkerRequest[] = [];
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        requests.push(request);
        return response(request);
      }),
    };
    const client = new YoloAutoClient(transport);

    const result = await client.evaluate(payload, "l2");

    expect(result).toEqual({
      status: "complete",
      l1: { verdict: "safe", accepted: true, complete: true, degraded: false },
      l2: { results: [], escalated: false },
      l3: undefined,
      escalated: false,
    });
    expect(requests).toHaveLength(2);
    expect(requests[0]).toMatchObject({ phase: "l1", deadlineMs: 250, payload });
    expect(requests[1]).toMatchObject({ phase: "l2", deadlineMs: 250, payload });
  });

  it("stops at L1 when configured with an L1 ceiling", async () => {
    const requests: YoloAutoWorkerRequest[] = [];
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        requests.push(request);
        return response(request);
      }),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l1")).resolves.toEqual({
      status: "complete",
      l1: { verdict: "safe", accepted: true, complete: true, degraded: false },
      l2: undefined,
      l3: undefined,
      escalated: false,
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ phase: "l1", deadlineMs: 250, payload });
  });

  it("does not run L2 after an unsafe L1 result", async () => {
    const requests: YoloAutoWorkerRequest[] = [];
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        requests.push(request);
        return response(request, {
          l1: { verdict: "unsafe", accepted: true, complete: true, degraded: false },
        });
      }),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l2")).resolves.toMatchObject({
      status: "complete",
      l1: { verdict: "unsafe" },
      l2: undefined,
      escalated: false,
    });
    expect(requests).toHaveLength(1);
  });

  it("runs L3 only after L2 requests escalation", async () => {
    const requests: YoloAutoWorkerRequest[] = [];
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        requests.push(request);
        if (request.phase === "l2") {
          return response(request, { l2: { results: [], escalated: true } });
        }
        return response(request, { l3: { recommendation: "prompt" } });
      }),
    };
    const client = new YoloAutoClient(transport);

    const result = await client.evaluate(payload, "l3");

    expect(result).toEqual({
      status: "complete",
      l1: { verdict: "safe", accepted: true, complete: true, degraded: false },
      l2: { results: [], escalated: true },
      l3: { recommendation: "prompt" },
      escalated: true,
    });
    expect(requests).toHaveLength(3);
    expect(requests[2]).toMatchObject({ phase: "l3", deadlineMs: 1000, payload });
    expect(requests[2].requestId).toBe(requests[0].requestId);
  });

  it("fails closed when L1 times out", async () => {
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(() => new Promise<YoloAutoWorkerResponse>(() => undefined)),
    };
    const client = new YoloAutoClient(transport, { l1RequestTimeoutMs: 5 });

    await expect(client.evaluate(payload, "l2")).resolves.toEqual({
      status: "unavailable",
      reason: "l1_request_failed",
      escalated: false,
    });
  });

  it("fails closed when L2 times out after safe L1", async () => {
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        if (request.phase === "l1") return response(request);
        throw new Error("timeout");
      }),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l2")).resolves.toEqual({
      status: "unavailable",
      reason: "l2_request_failed",
      escalated: false,
    });
  });

  it("does not exceed an L2 ceiling after escalation", async () => {
    const requests: YoloAutoWorkerRequest[] = [];
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        requests.push(request);
        if (request.phase === "l2") return response(request, { l2: { results: [], escalated: true } });
        return response(request, { l3: { recommendation: "prompt" } });
      }),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l2")).resolves.toEqual({
      status: "complete",
      l1: { verdict: "safe", accepted: true, complete: true, degraded: false },
      l2: { results: [], escalated: true },
      l3: undefined,
      escalated: true,
    });
    expect(requests.map((request) => request.phase)).toEqual(["l1", "l2"]);
  });

  it("uses L3 as default client ceiling", async () => {
    const requests: YoloAutoWorkerRequest[] = [];
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        requests.push(request);
        if (request.phase === "l2") return response(request, { l2: { results: [], escalated: true } });
        return response(request, { l3: { recommendation: "prompt" } });
      }),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload)).resolves.toMatchObject({
      status: "complete",
      l3: { recommendation: "prompt" },
      escalated: true,
    });
    expect(requests.map((request) => request.phase)).toEqual(["l1", "l2", "l3"]);
  });

  it("fails closed when escalated L3 times out", async () => {
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => {
        if (request.phase === "l1") return response(request);
        if (request.phase === "l2") {
          return response(request, { l2: { results: [], escalated: true } });
        }
        throw new Error("timeout");
      }),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l3")).resolves.toEqual({
      status: "unavailable",
      reason: "l3_request_failed",
      escalated: true,
    });
  });

  it("fails closed on malformed L1 results", async () => {
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => response(request, {
        l1: { verdict: "safe", accepted: "yes" as never, complete: true, degraded: false },
      })),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l2")).resolves.toEqual({
      status: "unavailable",
      reason: "protocol_mismatch",
      escalated: false,
    });
  });

  it("fails closed on malformed classifier results", async () => {
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => response(request, {
        l2: { results: "not-an-array" as never, escalated: false },
      })),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l2")).resolves.toEqual({
      status: "unavailable",
      reason: "protocol_mismatch",
      escalated: false,
    });
  });

  it("fails closed on malformed L3 recommendations", async () => {
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => request.phase === "l3"
        ? response(request, { l3: { recommendation: "allow-all" as never } })
        : request.phase === "l2"
          ? response(request, { l2: { results: [], escalated: true } })
          : response(request)),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l3")).resolves.toEqual({
      status: "unavailable",
      reason: "protocol_mismatch",
      escalated: true,
    });
  });

  it("fails closed on mismatched worker response ids", async () => {
    const transport: YoloAutoWorkerTransport = {
      request: vi.fn(async (request) => response({ ...request, requestId: "other" })),
    };
    const client = new YoloAutoClient(transport);

    await expect(client.evaluate(payload, "l2")).resolves.toMatchObject({
      status: "unavailable",
      reason: "protocol_mismatch",
    });
  });
});
