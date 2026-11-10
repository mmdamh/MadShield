// MadShield Guardian relay: a Cloudflare Worker that you deploy on your own account.
//
// What it is for: Mozilla's VPN service (Guardian, vpn.mozilla.org) refuses some regions by the address a request comes from
// (HTTP 451 "unavailable_in_region"). Foxy asks Guardian for its pass and quota over a plain HTTPS API; with this Worker in
// between, those few requests leave from Cloudflare's network instead of your phone's address. The VPN traffic itself,
// DNS, SOCKS and everything else never goes through it.
//
// What it does NOT do: it is not an open proxy. It forwards exactly three Guardian requests (below) to vpn.mozilla.org and
// refuses everything else. It stores nothing (no KV, no D1, no logs of requests), caches nothing and passes only the headers
// Guardian needs. It sees the account's access token while a request passes, which is why it is meant to be yours alone.
//
// The address in the app is   https://<your-worker>.workers.dev/<RELAY_SECRET>
// A request whose first path part is not the secret gets a plain 404, as if nothing were here.

const UPSTREAM = "https://vpn.mozilla.org";

// path -> methods Foxy uses (core/internal/guardian)
const ROUTES = {
  "/api/v1/fpn/token": ["GET", "HEAD"],
  "/api/v1/fpn/status": ["GET"],
  "/api/v1/fpn/activate": ["POST"],
};

// request headers passed on (everything else, the client's address included, is dropped)
const REQUEST_HEADERS = ["authorization", "content-type", "accept", "accept-language", "user-agent", "cache-control"];
// response headers passed back: the body type, Retry-After for a 429, and the quota Foxy shows
const RESPONSE_HEADERS = ["content-type", "retry-after", "x-quota-limit", "x-quota-remaining", "x-quota-reset"];

const MAX_BODY = 4096; // the activate call has no body; nothing here needs more

function notFound() {
  return new Response("Not found", { status: 404, headers: { "cache-control": "no-store" } });
}

// compares two strings without stopping at the first difference
function sameSecret(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

export default {
  async fetch(request, env) {
    const secret = env && env.RELAY_SECRET;
    if (typeof secret !== "string" || secret.length < 16) {
      // not set up: refuse everything rather than run open
      return new Response("RELAY_SECRET is not set (16 characters or more)", { status: 503, headers: { "cache-control": "no-store" } });
    }

    const url = new URL(request.url);
    const parts = url.pathname.split("/"); // ["", secret, "api", "v1", "fpn", ...]
    let given = "";
    try { given = decodeURIComponent(parts[1] || ""); } catch (e) { return notFound(); }
    if (parts.length < 3 || !sameSecret(given, secret)) return notFound();
    const path = "/" + parts.slice(2).join("/");

    // lets you check from the phone's browser that the Worker is reachable; it never contacts Mozilla
    if (path === "/ping" && (request.method === "GET" || request.method === "HEAD")) {
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } });
    }

    const methods = ROUTES[path];
    if (!methods) return notFound();
    if (!methods.includes(request.method)) {
      return new Response("Method not allowed", { status: 405, headers: { allow: methods.join(", "), "cache-control": "no-store" } });
    }

    const headers = new Headers();
    for (const name of REQUEST_HEADERS) {
      const v = request.headers.get(name);
      if (v) headers.set(name, v);
    }

    let body = undefined;
    if (request.method === "POST") {
      const buf = await request.arrayBuffer();
      if (buf.byteLength > MAX_BODY) return new Response("Too large", { status: 413, headers: { "cache-control": "no-store" } });
      if (buf.byteLength > 0) body = buf;
    }

    let upstream;
    try {
      upstream = await fetch(UPSTREAM + path, { method: request.method, headers, body, redirect: "manual", cf: { cacheTtl: 0, cacheEverything: false } });
    } catch (e) {
      return new Response("Mozilla did not answer", { status: 502, headers: { "cache-control": "no-store" } });
    }
    if (upstream.status >= 300 && upstream.status < 400) {
      return new Response("Unexpected redirect from Mozilla", { status: 502, headers: { "cache-control": "no-store" } });
    }

    const out = new Headers({ "cache-control": "no-store" });
    for (const name of RESPONSE_HEADERS) {
      const v = upstream.headers.get(name);
      if (v) out.set(name, v);
    }
    // the status is passed back as it is: a 451 stays a 451, a 401 stays a 401 (the app decides what they mean)
    return new Response(request.method === "HEAD" ? null : upstream.body, { status: upstream.status, headers: out });
  },
};
