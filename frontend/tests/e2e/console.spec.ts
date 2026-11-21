import { expect, test, type APIRequestContext } from "@playwright/test";

const api = "http://127.0.0.1:18080";
const principal = { "X-HostSec-Principal": "operator-alice" };

test("loopback API rejects missing identity, self-asserted roles, and live-scan flags", async ({ request }) => {
  const health = await request.get(`${api}/healthz`);
  expect(health.ok()).toBeTruthy();
  const body = (await health.json()) as { scan_ready: boolean; collector_available: boolean; execution_ready: boolean };
  expect(body.scan_ready).toBe(false);
  expect(body.collector_available).toBe(false);
  expect(body.execution_ready).toBe(false);

  const missing = await request.get(`${api}/v1/hosts`);
  expect(missing.status()).toBe(401);

  const hosts = await request.get(`${api}/v1/hosts?limit=20&offset=0`, { headers: principal });
  expect(hosts.ok()).toBeTruthy();
  const page = (await hosts.json()) as { items: Array<{ host_id: string }>; total: number };
  expect(page.total).toBe(1);
  expect(page.items[0]?.host_id).toBe("linux-test-001");
  expect(JSON.stringify(page)).not.toContain("auth_ref");

  const foreign = await request.get(`${api}/v1/hosts`, { headers: { "X-HostSec-Principal": "operator-zone-b" } });
  expect(foreign.ok()).toBeTruthy();
  const empty = (await foreign.json()) as { items: unknown[]; total: number };
  expect(empty.total).toBe(0);

  const role = await request.post(`${api}/v1/plans`, {
    headers: { ...principal, "Content-Type": "application/json" },
    data: { host_id: "linux-test-001", profile: "quick", role: "admin" }
  });
  expect(role.status()).toBe(403);

  const scan = await createFixtureScan(request);
  expect(scan.scan_ready).toBe(false);
  expect(scan.collector_available).toBe(false);
  expect(scan.status).toBe("PARTIAL");
});

test("console fetches real loopback hosts and PARTIAL jobs", async ({ page, request }) => {
  await page.goto("/");
  await expect(page.getByTestId("status-banner")).toContainText("Forbidden");

  await page.goto("/?principal=operator-zone-b");
  await expect(page.getByTestId("status-banner")).toContainText("Empty");
  await expect(page.getByText("No authorized hosts are visible to this principal.", { exact: true })).toBeVisible();

  await page.goto("/?principal=operator-alice");
  await expect(page.getByTestId("host-linux-test-001")).toBeVisible();

  const listed = await request.get(`${api}/v1/scans?limit=20&offset=0`, { headers: principal });
  expect(listed.ok()).toBeTruthy();
  const jobs = (await listed.json()) as { items: Array<{ scan_id: string }> };
  const scan = jobs.items[0] ?? (await createFixtureScan(request));
  await page.reload();
  await page.getByRole("button", { name: "Jobs" }).click();
  const job = page.getByTestId(`job-${scan.scan_id}`);
  await expect(job).toBeVisible();
  await expect(job.getByText(`${scan.scan_id} · PARTIAL`, { exact: true })).toBeVisible();
  await expect(page.getByText("Coverage is partial; this is not a clean bill of health.")).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

async function createFixtureScan(request: APIRequestContext) {
  const plan = await request.post(`${api}/v1/plans`, {
    headers: { ...principal, "Content-Type": "application/json" },
    data: { host_id: "linux-test-001", profile: "quick" }
  });
  expect(plan.ok()).toBeTruthy();
  const rec = (await plan.json()) as { plan_id: string };
  const scan = await request.post(`${api}/v1/scans`, {
    headers: { ...principal, "Content-Type": "application/json" },
    data: { plan_id: rec.plan_id, idempotency_key: `e2e-${Date.now()}` }
  });
  if (!scan.ok()) {
    throw new Error(await scan.text());
  }
  const payload = (await scan.json()) as {
    job: { scan_id: string; status: string; scan_ready: boolean; collector_available: boolean };
  };
  return payload.job;
}
