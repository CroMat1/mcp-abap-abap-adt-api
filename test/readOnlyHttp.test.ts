// BoundedHttpClient in sola lettura (red team 13/11/2026, DIF-1): GET sempre, POST solo
// sull'elenco chiuso READ_ONLY_POSTS, nessun altro metodo. Il trasporto e' finto: registra le
// chiamate, cosi' si vede che un rifiuto avviene prima della rete.
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { ADTClient } from "abap-adt-api";
import {
  BoundedHttpClient,
  READ_ONLY_POSTS,
  readOnlyRequestAllowed,
  requestContext,
} from "../src/lib/http.js";

const BASE = new URL("https://sap.example.invalid");

/** Trasporto finto con la forma di node:http.request: risponde 200 a tutto e registra. */
function fakeTransport() {
  const calls: { method: string; path: string; search: string }[] = [];
  const transport = ((url: URL, options: any, callback: (res: any) => void) => {
    calls.push({ method: options.method, path: url.pathname, search: url.search });
    const req: any = new EventEmitter();
    req.end = () => {
      setImmediate(() => {
        const res: any = new EventEmitter();
        res.statusCode = 200;
        res.statusMessage = "OK";
        res.headers = { "content-type": "text/plain", "x-csrf-token": "fixture-token" };
        res.destroy = () => {};
        callback(res);
        res.emit("data", Buffer.from("ok"));
        res.emit("end");
      });
    };
    return req;
  }) as any;
  return { calls, transport };
}

const inContext = <T>(fn: () => Promise<T>) =>
  requestContext.run({ signal: new AbortController().signal }, fn);

test("unita': GET si', POST solo in elenco (percorso esatto e query), altri metodi mai", () => {
  const u = (p: string) => new URL(p, BASE);
  assert.equal(readOnlyRequestAllowed("GET", u("/sap/bc/adt/cts/transportrequests/X/newreleasejobs")), true);
  for (const p of READ_ONLY_POSTS) {
    const url = u(p.path);
    for (const [k, v] of Object.entries(p.query ?? {})) url.searchParams.set(k, v);
    assert.equal(readOnlyRequestAllowed("POST", url), true, p.path);
    for (const m of ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
      assert.equal(readOnlyRequestAllowed(m, url), false, `${m} ${p.path}`);
  }
  for (const p of [
    "/sap/bc/adt/cts/transportrequests/DEVK900001/newreleasejobs",
    "/sap/bc/adt/activation",
    "/sap/bc/adt/refactorings",
    "/sap/bc/adt/debugger",
    "/sap/bc/adt/atc/worklists",
    "/sap/bc/adt/atc/items",
    "/sap/bc/adt/abapgit/externalrepoinfo",
    "/sap/bc/adt/quickfixes/evaluation",
    "/sap/bc/adt/datapreview/freestyle/",
    "/sap/bc/adt/datapreview/freestyle/x",
    "/sap/bc/adt/datapreview/freestyle;x",
    "/sap/bc/adt/datapreview/%66reestyle",
    "/SAP/BC/ADT/DATAPREVIEW/FREESTYLE",
    "/sap/bc/adt/abapsource/prettyprinter/settings",
  ])
    assert.equal(readOnlyRequestAllowed("POST", u(p)), false, p);
  // La query che distingue la voce e' obbligatoria, unica e con il valore giusto.
  assert.equal(readOnlyRequestAllowed("POST", u("/sap/bc/adt/checkruns")), false);
  assert.equal(readOnlyRequestAllowed("POST", u("/sap/bc/adt/checkruns?reporters=atcChecker")), false);
  assert.equal(
    readOnlyRequestAllowed("POST", u("/sap/bc/adt/checkruns?reporters=abapCheckRun&reporters=x")),
    false,
  );
  assert.equal(readOnlyRequestAllowed("POST", u("/sap/bc/adt/checkruns?reporters=abapCheckRun")), true);
});

test("client: POST fuori elenco rifiutata prima della rete; GET e POST in elenco passano", async () => {
  const f = fakeTransport();
  const http = new BoundedHttpClient(BASE, { transport: f.transport });
  assert.equal(http.readOnly, true, "senza opzioni il client e' in sola lettura");
  await inContext(async () => {
    await assert.rejects(
      http.request({ url: "/sap/bc/adt/cts/transportrequests/DEVK900001/newreleasejobs", method: "POST" } as any),
      /read-only/,
    );
    await assert.rejects(http.request({ url: "/sap/bc/adt/atc/items", method: "PUT" } as any), /read-only/);
    await assert.rejects(http.request({ url: "/sap/bc/adt/debugger/listeners", method: "DELETE" } as any), /read-only/);
    // La query della voce si controlla dopo aver applicato `qs`: non basta metterla nell'URL.
    await assert.rejects(
      http.request({ url: "/sap/bc/adt/checkruns?reporters=abapCheckRun", method: "POST", qs: { reporters: "x" } } as any),
      /read-only/,
    );
    assert.equal(f.calls.length, 0, "nessuna richiesta deve partire");

    const get = await http.request({ url: "/sap/bc/adt/repository/informationsystem/search", qs: { query: "Z*" } } as any);
    assert.equal(get.status, 200);
    const post = await http.request({
      url: "/sap/bc/adt/checkruns?reporters=abapCheckRun",
      method: "POST",
      body: "<x/>",
    } as any);
    assert.equal(post.status, 200);
  });
  assert.deepEqual(
    f.calls.map((c) => `${c.method} ${c.path}`),
    ["GET /sap/bc/adt/repository/informationsystem/search", "POST /sap/bc/adt/checkruns"],
  );
});

test("client fuori dalla sola lettura (SAP_READ_ONLY=0): le scritture passano come prima", async () => {
  const f = fakeTransport();
  const http = new BoundedHttpClient(BASE, { readOnly: false, transport: f.transport });
  await inContext(async () => {
    const r = await http.request({ url: "/sap/bc/adt/activation", method: "POST" } as any);
    assert.equal(r.status, 200);
  });
  assert.deepEqual(f.calls.map((c) => c.method), ["POST"]);
});

test("attacco red team nella libreria: checkRepo con check_link verso una release, solo il login GET parte", async () => {
  const f = fakeTransport();
  const client = new ADTClient(
    new BoundedHttpClient(BASE, { transport: f.transport }),
    "fixture-user",
    "fixture-password",
    "100",
    "",
  );
  const repo: any = {
    key: "000001",
    links: [{ type: "check_link", rel: "check", href: "/sap/bc/adt/cts/transportrequests/DEVK900001/newreleasejobs" }],
  };
  await inContext(async () => {
    await assert.rejects(client.checkRepo(repo), /read-only/);
  });
  assert.ok(f.calls.every((c) => c.method === "GET"), JSON.stringify(f.calls));
  assert.ok(!f.calls.some((c) => c.path.includes("transportrequests")));
});

test("letture reali della libreria che fanno POST passano dal client in sola lettura", async () => {
  const f = fakeTransport();
  const client = new ADTClient(
    new BoundedHttpClient(BASE, { transport: f.transport }),
    "fixture-user",
    "fixture-password",
    "100",
    "",
  );
  await inContext(async () => {
    await client.login();
    // Le risposte finte non sono XML valido: conta solo che la POST sia partita.
    await client.findObjectPath("/sap/bc/adt/programs/programs/ztest").catch(() => {});
    await client.syntaxCheck("/sap/bc/adt/ddic/ddl/sources/zcds").catch(() => {});
    await client.runQuery("SELECT * FROM t000", 1).catch(() => {});
    await client.loadTypes().catch(() => {});
    await client.prettyPrinter("report z.").catch(() => {});
  });
  const posts = f.calls.filter((c) => c.method === "POST").map((c) => c.path);
  assert.deepEqual(posts, [
    "/sap/bc/adt/repository/nodepath",
    "/sap/bc/adt/checkruns",
    "/sap/bc/adt/datapreview/freestyle",
    "/sap/bc/adt/repository/typestructure",
    "/sap/bc/adt/abapsource/prettyprinter",
  ]);
});
