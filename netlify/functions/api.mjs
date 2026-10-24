import { getStore } from "@netlify/blobs";
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { createHmac, timingSafeEqual } from "node:crypto";

const json = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

// Token de sesión (12 h) que se entrega al entrar con huella
const sign = (e) => createHmac("sha256", process.env.EDIT_PIN + "|status").update(String(e)).digest("base64url");
const mkToken = () => { const e = Date.now() + 12 * 3600e3; return e + "." + sign(e); };
const okToken = (t) => {
  if (!t) return false;
  const [e, m] = t.split(".");
  if (!e || !m || +e < Date.now()) return false;
  const a = Buffer.from(sign(e)), b = Buffer.from(m);
  return a.length === b.length && timingSafeEqual(a, b);
};

export default async (req) => {
  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api\//, "");
    const rpID = url.hostname;
    const origin = req.headers.get("origin") || url.origin;
    const pin = process.env.EDIT_PIN;
    const store = getStore("status");
    const ok = !!pin && (req.headers.get("x-pin") === pin || okToken(req.headers.get("x-token")));
    const creds = async () => (await store.get("cred", { type: "json" })) || [];
    const chal = async (k) => {
      const c = await store.get(k, { type: "json" });
      return c && Date.now() - c.t < 5 * 60e3 ? c.c : null;
    };

    if (path === "login") return ok ? json({ ok: true }) : json({ ok: false }, 401);

    if (path === "data") {
      if (req.method === "GET") return json((await store.get("db", { type: "json" })) || {});
      if (!ok) return json({ error: "No autorizado" }, 401);
      await store.setJSON("db", await req.json());
      return json({ ok: true });
    }

    if (path === "huella") return json({ registrada: (await creds()).length > 0 });

    if (path === "reg-options") {
      if (!ok) return json({ error: "No autorizado" }, 401);
      const cs = await creds();
      const o = await generateRegistrationOptions({
        rpName: "Mi Status Semanal", rpID, userName: "kevin", attestationType: "none",
        excludeCredentials: cs.map((c) => ({ id: c.id, transports: c.transports })),
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      });
      await store.setJSON("chal-reg", { c: o.challenge, t: Date.now() });
      return json(o);
    }

    if (path === "reg-verify") {
      if (!ok) return json({ error: "No autorizado" }, 401);
      const expectedChallenge = await chal("chal-reg");
      if (!expectedChallenge) return json({ error: "Expirado" }, 400);
      const v = await verifyRegistrationResponse({
        response: await req.json(), expectedChallenge,
        expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
      });
      if (!v.verified) return json({ error: "No verificado" }, 400);
      const c = v.registrationInfo.credential;
      const cs = await creds();
      cs.push({ id: c.id, publicKey: Buffer.from(c.publicKey).toString("base64url"), counter: c.counter, transports: c.transports || [] });
      await store.setJSON("cred", cs);
      return json({ ok: true });
    }

    if (path === "auth-options") {
      const cs = await creds();
      if (!cs.length) return json({ error: "Sin huella registrada" }, 404);
      const o = await generateAuthenticationOptions({
        rpID, userVerification: "required",
        allowCredentials: cs.map((c) => ({ id: c.id, transports: c.transports })),
      });
      await store.setJSON("chal-auth", { c: o.challenge, t: Date.now() });
      return json(o);
    }

    if (path === "auth-verify") {
      const r = await req.json();
      const cs = await creds();
      const c = cs.find((x) => x.id === r.id);
      const expectedChallenge = await chal("chal-auth");
      if (!c || !expectedChallenge || !pin) return json({ error: "No autorizado" }, 401);
      const v = await verifyAuthenticationResponse({
        response: r, expectedChallenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
        credential: { id: c.id, publicKey: Buffer.from(c.publicKey, "base64url"), counter: c.counter, transports: c.transports },
      });
      if (!v.verified) return json({ error: "No verificado" }, 401);
      c.counter = v.authenticationInfo.newCounter;
      await store.setJSON("cred", cs);
      return json({ ok: true, token: mkToken() });
    }

    return json({ error: "No encontrado" }, 404);
  } catch (e) {
    return json({ error: String(e.message || e) }, 400);
  }
};

export const config = { path: "/api/*" };
