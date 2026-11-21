import { describe, expect, it, vi } from "vitest";
import { fetchSnapshot } from "../src/shared/api/client";
import { resolveLoopbackAPIBase, resolvePrincipal } from "../src/shared/api/loopback";

describe("local API client", () => {
  it("raises forbidden instead of inventing hosts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("denied", { status: 403 }))
    );
    await expect(fetchSnapshot("http://127.0.0.1:18080", "operator-zone-b")).rejects.toThrow("forbidden");
    vi.unstubAllGlobals();
  });

  it("reads paginated hosts and jobs from the loopback API", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo) => {
      const url = String(input);
      expect(url.startsWith("http://127.0.0.1:18080/")).toBe(true);
      if (url.includes("/v1/hosts")) {
        return Response.json({
          items: [{ host_id: "linux-test-001", zone: "zone-a", business_system: "lab", authorized: true }],
          total: 1,
          limit: 20,
          offset: 0,
          next_offset: null
        });
      }
      if (url.includes("/v1/scans") && url.includes("findings")) {
        return Response.json({
          findings: { items: [], total: 0, limit: 20, offset: 0, next_offset: null },
          rule_results: [{ rule_id: "proc-listening", outcome: "PASS", reason_code: "ok" }]
        });
      }
      if (url.includes("/v1/scans")) {
        return Response.json({
          items: [
            {
              scan_id: "scan-local-1",
              host_id: "linux-test-001",
              status: "PARTIAL",
              collector_available: false,
              scan_ready: false,
              limitations: ["fixture inspect is not enterprise host scanning"]
            }
          ],
          total: 1,
          limit: 20,
          offset: 0,
          next_offset: null
        });
      }
      return new Response("missing", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const snapshot = await fetchSnapshot("http://127.0.0.1:18080", "operator-alice");
    expect(snapshot.hosts).toEqual([
      { host_id: "linux-test-001", zone: "zone-a", business_system: "lab", authorized: true }
    ]);
    expect(snapshot.jobs[0]?.status).toBe("PARTIAL");
    expect(snapshot.jobs[0]?.scan_ready).toBe(false);
    expect(snapshot.rules[0]?.rule_id).toBe("proc-listening");
    vi.unstubAllGlobals();
  });

  it("accepts only loopback API bases and query principals", () => {
    expect(resolvePrincipal("?principal=operator-alice")).toBe("operator-alice");
    expect(resolveLoopbackAPIBase("?api=http://127.0.0.1:18080")).toBe("http://127.0.0.1:18080");
    expect(() => resolveLoopbackAPIBase("?api=https://evil.example")).toThrow(/loopback/);
  });
});
