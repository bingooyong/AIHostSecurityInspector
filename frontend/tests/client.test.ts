import { describe, expect, it, vi } from "vitest";
import { fetchSnapshot } from "../src/shared/api/client";

describe("local API client", () => {
  it("raises forbidden instead of inventing hosts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("denied", { status: 403 }))
    );
    await expect(fetchSnapshot("http://127.0.0.1:18080", "operator-zone-b")).rejects.toThrow("forbidden");
    vi.unstubAllGlobals();
  });
});
