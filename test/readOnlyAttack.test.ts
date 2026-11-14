// Red team 13/11/2026, difese-mcp.md §1 (DIF-1): in sola lettura `checkRepo` faceva POST su PROD
// verso un `href` scelto da chi chiama. Qui l'attacco si riproduce contro un SAP finto in locale,
// che registra ogni richiesta ricevuta: in sola lettura nessuna POST deve arrivarci.
// Usa solo API che esistevano gia' prima della correzione, cosi' lo stesso file mostra il
// fallimento sul codice vecchio.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as httpServer } from "node:http";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { ADTClient } from "abap-adt-api";
import { Runtime } from "../src/server.js";
import { BoundedHttpClient, requestContext } from "../src/lib/http.js";

const RELEASE = "/sap/bc/adt/cts/transportrequests/DEVK900001/newreleasejobs";
const attackRepo = {
  key: "000001",
  sapPackage: "ZPKG",
  url: "https://example.invalid/repo.git",
  branch_name: "refs/heads/main",
  created_by: "X",
  created_at: {},
  links: [{ type: "check_link", rel: "check", href: RELEASE }],
};

async function fakeSap() {
  const requests: { method: string; path: string }[] = [];
  const server = httpServer((req, res) => {
    requests.push({ method: req.method!, path: new URL(req.url!, "http://x").pathname });
    req.resume();
    req.on("end", () => {
      res.writeHead(200, {
        "content-type": "text/plain",
        "x-csrf-token": "fixture-token",
        "set-cookie": "SAP_SESSIONID=fixture; path=/",
      });
      res.end("ok");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  return {
    base,
    requests,
    writes: () => requests.filter((r) => r.method !== "GET"),
    close: async () => {
      server.closeAllConnections();
      server.close();
      await once(server, "close");
    },
  };
}

test("sola lettura: tools/list e' esattamente l'elenco chiuso tools-readonly.txt", async () => {
  const r = new Runtime({});
  try {
    const exposed = [...r.exposedTools.map((t) => t.definition.name), "healthcheck", "readResultPage"].sort();
    const frozen = readFileSync(new URL("../tools-readonly.txt", import.meta.url), "utf8")
      .split(/\r?\n/)
      .filter(Boolean)
      .sort();
    assert.deepEqual(exposed, frozen);
    for (const n of [
      "checkRepo",
      "fixEdits",
      "atcCheckVariant",
      "reentranceTicket",
      "gitExternalRepoInfo",
      "remoteRepoInfo",
    ])
      assert.ok(!exposed.includes(n), `${n} non deve essere esposto in sola lettura`);
  } finally {
    await r.close();
  }
});

test("attacco checkRepo (repo.links[].href = release di trasporto): rifiutato, nessuna POST arriva a SAP", async () => {
  const f = await fakeSap();
  const r = new Runtime({
    SAP_URL: f.base,
    SAP_USER: "fixture-user",
    SAP_PASSWORD: "fixture-password",
    SAP_CLIENT: "100",
  });
  try {
    await assert.rejects(r.invoke("checkRepo", { repo: attackRepo }), /read-only/);
    assert.deepEqual(f.writes(), []);
  } finally {
    await r.close();
    await f.close();
  }
});

test("attacco checkRepo nella libreria, con il client HTTP del server: la POST e' rifiutata prima della rete", async () => {
  const f = await fakeSap();
  try {
    const client = new ADTClient(
      new BoundedHttpClient(new URL(f.base)),
      "fixture-user",
      "fixture-password",
      "100",
      "",
    );
    const abort = new AbortController();
    await requestContext.run({ signal: abort.signal }, async () => {
      await assert.rejects(client.checkRepo(attackRepo as any), /read-only/);
    });
    // Il login (GET) puo' passare; la POST verso l'href no.
    assert.deepEqual(f.writes(), []);
    assert.ok(!f.requests.some((q) => q.path === RELEASE), "l'href non deve essere raggiunto");
  } finally {
    await f.close();
  }
});

test("client HTTP in sola lettura (default): POST, PUT, DELETE fuori elenco rifiutate, nessuna richiesta parte", async () => {
  const f = await fakeSap();
  try {
    const http = new BoundedHttpClient(new URL(f.base));
    const abort = new AbortController();
    await requestContext.run({ signal: abort.signal }, async () => {
      for (const method of ["POST", "PUT", "DELETE", "PATCH", "post"])
        await assert.rejects(http.request({ url: RELEASE, method } as any), /read-only/, method);
      await assert.rejects(
        http.request({ url: "/sap/bc/adt/activation", method: "POST", qs: { method: "activate" } } as any),
        /read-only/,
      );
    });
    assert.deepEqual(f.requests, []);
  } finally {
    await f.close();
  }
});
