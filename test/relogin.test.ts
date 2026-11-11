// Auto-relogin in sola lettura. Nessun contatto con SAP: un finto server ADT in locale
// simula sessione e CSRF scaduti (403 + x-csrf-token: Required, come SAP).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as httpServer } from "node:http";
import { once } from "node:events";
import { Runtime, isSessionExpired, type SessionEvent } from "../src/server.js";
import { requestContext } from "../src/lib/http.js";
import { autoReloginMode } from "../src/toolPolicy.js";

const url = "/sap/bc/adt/programs/programs/ztest/source/main";

async function fakeSap(extraEnv: Record<string, string> = {}) {
  const state = {
    logins: 0,
    sessionValid: false,
    alwaysExpired: false,
    loginFails: false,
    sourceCalls: 0,
  };
  const server = httpServer(async (req, res) => {
    for await (const _ of req);
    const path = new URL(req.url!, "http://fake").pathname;
    if (path === "/sap/bc/adt/compatibility/graph") {
      // dropSession manda la stessa GET in modalita' stateless: chiude il contesto.
      if (req.headers["x-sap-adt-sessiontype"] === "stateless") {
        state.sessionValid = false;
        res.end("<graph/>");
        return;
      }
      state.logins++;
      if (state.loginFails) {
        res.writeHead(401, { "content-type": "text/plain" });
        res.end("");
        return;
      }
      state.sessionValid = true;
      res.setHeader("x-csrf-token", `csrf-${state.logins}`);
      res.setHeader("set-cookie", [`SAP_SESSIONID=s${state.logins}; Path=/`]);
      res.end("<graph/>");
      return;
    }
    if (path === url) {
      state.sourceCalls++;
      if (state.alwaysExpired || !state.sessionValid) {
        res.writeHead(403, {
          "x-csrf-token": "Required",
          "content-type": "text/plain",
        });
        res.end("CSRF token validation failed");
        return;
      }
      res.end("REPORT ztest.");
      return;
    }
    res.end("<ok/>");
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const runtime = new Runtime({
    SAP_URL: `http://127.0.0.1:${(server.address() as any).port}`,
    SAP_USER: "fake-user",
    SAP_PASSWORD: "fake-password",
    SAP_CLIENT: "100",
    SAP_REQUEST_TIMEOUT_MS: "5000",
    ...extraEnv,
  });
  const events: SessionEvent[] = [];
  runtime.sessionLog = (e) => events.push(e);
  return {
    runtime,
    state,
    events,
    read: () => runtime.invoke("getObjectSource", { objectSourceUrl: url }),
    close: async () => {
      await runtime.close();
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}

test("SAP_AUTO_RELOGIN: attivo per default, spento solo da 0 o false", () => {
  assert.equal(autoReloginMode({}), true);
  assert.equal(autoReloginMode({ SAP_AUTO_RELOGIN: "1" }), true);
  assert.equal(autoReloginMode({ SAP_AUTO_RELOGIN: "0" }), false);
  assert.equal(autoReloginMode({ SAP_AUTO_RELOGIN: " FALSE " }), false);
  assert.equal(new Runtime({}).autoRelogin, true);
  assert.equal(new Runtime({ SAP_READ_ONLY: "0" }).autoRelogin, false);
});

test("isSessionExpired riconosce solo CSRF e 401", () => {
  assert.equal(isSessionExpired(undefined), false);
  assert.equal(isSessionExpired(new Error("x")), false);
});

test("sola lettura: scadenza -> relogin -> retry ok, evento senza credenziali", async () => {
  const f = await fakeSap();
  try {
    await f.read(); // primo login implicito
    assert.equal(f.state.logins, 1);
    f.state.sessionValid = false; // inattivita': SAP ha chiuso la sessione
    const r = await f.read();
    assert.equal(f.state.logins, 2);
    assert.match(JSON.stringify(r), /REPORT ztest/);
    assert.deepEqual(f.events, [
      { event: "sap_session_relogin", tool: "getObjectSource", outcome: "retry_ok" },
    ]);
    assert.doesNotMatch(JSON.stringify(f.events), /fake-password|fake-user|csrf-/);
  } finally {
    await f.close();
  }
});

test("sola lettura: doppio fallimento -> un solo relogin e l'errore originale", async () => {
  const f = await fakeSap();
  try {
    await f.read();
    f.state.alwaysExpired = true;
    const calls = f.state.sourceCalls;
    await assert.rejects(f.read(), /CSRF token expired/);
    assert.equal(f.state.logins, 2, "un solo relogin");
    assert.equal(f.state.sourceCalls - calls, 2, "richiesta ripetuta una sola volta");
    assert.deepEqual(
      f.events.map((e) => e.outcome),
      ["retry_failed"],
    );
  } finally {
    await f.close();
  }
});

test("sola lettura: relogin rifiutato -> errore originale, nessun retry", async () => {
  const f = await fakeSap();
  try {
    await f.read();
    f.state.sessionValid = false;
    f.state.loginFails = true;
    const calls = f.state.sourceCalls;
    await assert.rejects(f.read(), /CSRF token expired/);
    assert.equal(f.state.sourceCalls - calls, 1);
    assert.deepEqual(
      f.events.map((e) => e.outcome),
      ["relogin_failed"],
    );
  } finally {
    await f.close();
  }
});

test("modalita' non read-only: nessun relogin, comportamento di prima", async () => {
  const f = await fakeSap({ SAP_READ_ONLY: "0" });
  try {
    await f.read();
    f.state.sessionValid = false;
    await assert.rejects(f.read(), /explicitly login again/);
    assert.equal(f.state.logins, 1);
    assert.equal(f.events.length, 0);
  } finally {
    await f.close();
  }
});

test("SAP_AUTO_RELOGIN=0 in sola lettura: nessun relogin", async () => {
  const f = await fakeSap({ SAP_AUTO_RELOGIN: "0" });
  try {
    await f.read();
    f.state.sessionValid = false;
    await assert.rejects(f.read(), /explicitly login again/);
    assert.equal(f.state.logins, 1);
  } finally {
    await f.close();
  }
});

test("dropSession di un altro agente: la lettura successiva si riprende da sola", async () => {
  const f = await fakeSap();
  try {
    await f.read();
    await f.runtime.invoke("dropSession", {});
    assert.equal(f.state.sessionValid, false);
    const r = await f.read();
    assert.match(JSON.stringify(r), /REPORT ztest/);
    assert.equal(f.state.logins, 2);
  } finally {
    await f.close();
  }
});

test("due relogin concorrenti -> un solo login (promessa condivisa)", async () => {
  const f = await fakeSap();
  try {
    const abort = new AbortController();
    await requestContext.run({ signal: abort.signal }, () =>
      Promise.all([f.runtime.relogin(), f.runtime.relogin(), f.runtime.relogin()]),
    );
    assert.equal(f.state.logins, 1);
    // finita la promessa, un relogin successivo ne apre uno nuovo
    await requestContext.run({ signal: abort.signal }, () => f.runtime.relogin());
    assert.equal(f.state.logins, 2);
  } finally {
    await f.close();
  }
});

test("due letture concorrenti scadute: la seconda e' rifiutata come busy, un solo login", async () => {
  const f = await fakeSap();
  try {
    await f.read();
    f.state.sessionValid = false;
    const [a, b] = await Promise.allSettled([f.read(), f.read()]);
    assert.equal(a.status, "fulfilled");
    assert.equal(b.status, "rejected");
    assert.match(String((b as PromiseRejectedResult).reason?.message), /busy/);
    assert.equal(f.state.logins, 2);
  } finally {
    await f.close();
  }
});
