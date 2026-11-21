const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost"]);

export function resolvePrincipal(search = window.location.search): string {
  return new URLSearchParams(search).get("principal")?.trim() ?? "";
}

export function resolveLoopbackAPIBase(search = window.location.search): string {
  const raw = new URLSearchParams(search).get("api") ?? "http://127.0.0.1:18080";
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("api base is invalid");
  }
  if (parsed.protocol !== "http:" || !LOOPBACK_HOSTS.has(parsed.hostname)) {
    throw new Error("api base must be loopback http");
  }
  return parsed.origin;
}
