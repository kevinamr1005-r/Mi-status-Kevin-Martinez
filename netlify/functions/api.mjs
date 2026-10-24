import { getStore } from "@netlify/blobs";

const json = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

export default async (req) => {
  const pin = process.env.EDIT_PIN;
  const ok = !!pin && req.headers.get("x-pin") === pin;
  const path = new URL(req.url).pathname;

  if (path.endsWith("/login")) return ok ? json({ ok: true }) : json({ ok: false }, 401);

  const store = getStore("status");
  if (req.method === "GET") return json((await store.get("db", { type: "json" })) || {});
  if (req.method === "POST") {
    if (!ok) return json({ error: "PIN incorrecto" }, 401);
    await store.setJSON("db", await req.json());
    return json({ ok: true });
  }
  return json({ error: "Método no permitido" }, 405);
};

export const config = { path: "/api/*" };
