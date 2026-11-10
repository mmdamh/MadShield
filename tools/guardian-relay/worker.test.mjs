// Run: node tools/guardian-relay/worker.test.mjs   (Node 18 or newer; no packages)
import worker from "./worker.js";

const SECRET = "s3cret-s3cret-s3cret";
const env = { RELAY_SECRET: SECRET };
let failed = 0;
const check = (name, ok) => { console.log((ok ? "ok:   " : "FAIL: ") + name); if (!ok) failed++; };

let seen = null;
let reply = () => new Response('{"token":"x"}', { status: 200, headers: { "content-type": "application/json", "x-quota-limit": "100", "x-quota-remaining": "90", "x-quota-reset": "2026-12-01", "set-cookie": "a=b", "x-evil": "1" } });
globalThis.fetch = async (url, init) => { seen = { url, init }; return reply(); };

const call = (path, init = {}, e = env) => worker.fetch(new Request("https://relay.example.workers.dev" + path, init), e);
const hdr = (h) => (seen && seen.init.headers.get(h));

{
  const r = await call(`/${SECRET}/api/v1/fpn/token`, { headers: { Authorization: "Bearer abc", "X-Forwarded-For": "5.6.7.8", "CF-Connecting-IP": "5.6.7.8", Cookie: "k=v", "User-Agent": "Firefox/1", Accept: "*/*" } });
  check("token: GET is passed to Guardian", r.status === 200 && seen.url === "https://vpn.mozilla.org/api/v1/fpn/token" && seen.init.method === "GET");
  check("token: the bearer token is passed", hdr("authorization") === "Bearer abc");
  check("token: client address and cookies are dropped", hdr("x-forwarded-for") === null && hdr("cf-connecting-ip") === null && hdr("cookie") === null);
  check("token: quota headers come back, others do not", r.headers.get("x-quota-limit") === "100" && r.headers.get("x-quota-remaining") === "90" && r.headers.get("x-quota-reset") === "2026-12-01" && r.headers.get("set-cookie") === null && r.headers.get("x-evil") === null);
  check("token: the answer is never cached", r.headers.get("cache-control") === "no-store");
  check("token: the body arrives", (await r.text()) === '{"token":"x"}');
}
{
  const r = await call(`/${SECRET}/api/v1/fpn/token`, { method: "HEAD", headers: { Authorization: "Bearer abc" } });
  check("token: HEAD works and has no body", r.status === 200 && seen.init.method === "HEAD" && (await r.text()) === "");
}
{
  await call(`/${SECRET}/api/v1/fpn/status`, { headers: { Authorization: "Bearer abc" } });
  check("status: passed", seen.url === "https://vpn.mozilla.org/api/v1/fpn/status");
}
{
  const r = await call(`/${SECRET}/api/v1/fpn/activate`, { method: "POST", headers: { Authorization: "Bearer abc" } });
  check("activate: POST passed", r.status === 200 && seen.init.method === "POST" && seen.url === "https://vpn.mozilla.org/api/v1/fpn/activate");
}
{
  reply = () => new Response('{"error":"unavailable_in_region"}', { status: 451, headers: { "content-type": "application/json" } });
  const r = await call(`/${SECRET}/api/v1/fpn/token`, { headers: { Authorization: "Bearer abc" } });
  check("451 stays 451 with its body", r.status === 451 && (await r.text()).includes("unavailable_in_region"));
  reply = () => new Response("", { status: 302, headers: { location: "https://evil.example/" } });
  const r2 = await call(`/${SECRET}/api/v1/fpn/token`, { headers: { Authorization: "Bearer abc" } });
  check("a redirect is not followed or passed on", r2.status === 502 && r2.headers.get("location") === null);
  reply = () => { throw new Error("network"); };
  const r3 = await call(`/${SECRET}/api/v1/fpn/token`, { headers: { Authorization: "Bearer abc" } });
  check("Mozilla not answering is a 502", r3.status === 502);
  reply = () => new Response('{"token":"x"}', { status: 200 });
}
{
  seen = null;
  const wrong = [`/%E0%A4%A/api/v1/fpn/token`, `/wrong/api/v1/fpn/token`, `/api/v1/fpn/token`, `/`, `/${SECRET}x/api/v1/fpn/token`, `/${SECRET.slice(1)}/api/v1/fpn/token`];
  const results = await Promise.all(wrong.map((p) => call(p)));
  check("a wrong or missing secret is a plain 404", results.every((r) => r.status === 404) && seen === null);
}
{
  seen = null;
  const other = [`/${SECRET}/api/v1/fpn/other`, `/${SECRET}/`, `/${SECRET}/api/v1/fpn/token/extra`, `/${SECRET}/../etc`, `/${SECRET}//vpn.mozilla.org/api/v1/fpn/token`, `/${SECRET}/https://evil.example/`];
  const results = await Promise.all(other.map((p) => call(p, { headers: { Authorization: "Bearer a" } })));
  check("any other path is refused and nothing is sent", results.every((r) => r.status === 404) && seen === null);
  const m = await call(`/${SECRET}/api/v1/fpn/token`, { method: "POST" });
  const m2 = await call(`/${SECRET}/api/v1/fpn/activate`, { method: "GET" });
  check("a method Foxy does not use is 405 and nothing is sent", m.status === 405 && m2.status === 405 && seen === null);
}
{
  seen = null;
  const r = await call(`/${SECRET}/ping`);
  check("ping answers without contacting Mozilla", r.status === 200 && seen === null && (await r.json()).ok === true);
}
{
  seen = null;
  const big = new Uint8Array(5000);
  const r = await call(`/${SECRET}/api/v1/fpn/activate`, { method: "POST", body: big, headers: { Authorization: "Bearer a" } });
  check("a big body is refused", r.status === 413 && seen === null);
}
{
  seen = null;
  const r1 = await call(`/x/api/v1/fpn/token`, {}, {});
  const r2 = await call(`/short/api/v1/fpn/token`, {}, { RELAY_SECRET: "short" });
  check("without a long enough secret everything is refused (503)", r1.status === 503 && r2.status === 503 && seen === null);
}
console.log(failed ? `${failed} FAILED` : "ALL PASSED");
process.exit(failed ? 1 : 0);
